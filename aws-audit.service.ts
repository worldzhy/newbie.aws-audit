import {BadRequestException, Injectable, NotFoundException} from '@nestjs/common';
import {PrismaService} from '@framework/prisma/prisma.service';
import {AwsCredentialService} from '@microservices/aws-core/aws-credential.service';
import {getCallerIdentity} from '@microservices/aws-core/aws-sts.helper';
import {
  EC2Client,
  DescribeInstancesCommand,
  DescribeSecurityGroupsCommand,
  SecurityGroup,
} from '@aws-sdk/client-ec2';
import {RDSClient, DescribeDBInstancesCommand} from '@aws-sdk/client-rds';
import {
  GetBucketAclCommand,
  GetBucketEncryptionCommand,
  GetBucketLocationCommand,
  GetBucketPolicyStatusCommand,
  GetBucketVersioningCommand,
  GetPublicAccessBlockCommand,
  S3Client,
  ListBucketsCommand,
} from '@aws-sdk/client-s3';
import {
  GenerateCredentialReportCommand,
  GetAccountPasswordPolicyCommand,
  GetCredentialReportCommand,
  GetGroupPolicyCommand,
  GetPolicyCommand,
  GetPolicyVersionCommand,
  GetRolePolicyCommand,
  GetUserPolicyCommand,
  IAMClient,
  ListAttachedGroupPoliciesCommand,
  ListAttachedRolePoliciesCommand,
  ListAttachedUserPoliciesCommand,
  ListGroupPoliciesCommand,
  ListGroupsCommand,
  ListGroupsForUserCommand,
  ListRolePoliciesCommand,
  ListRolesCommand,
  ListUserPoliciesCommand,
  ListUsersCommand,
} from '@aws-sdk/client-iam';

type Severity = 'high' | 'medium' | 'low';
type ScanStatus = 'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED';

interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
}

interface AuditFinding {
  service: 'iam' | 's3' | 'ec2' | 'rds' | 'sts';
  severity: Severity;
  resourceType: string;
  resourceId: string;
  title: string;
  detail: string;
  recommendation?: string;
  region?: string | null;
}

interface AuditError {
  service: 'iam' | 's3' | 'ec2' | 'rds' | 'sts';
  message: string;
}

interface CredentialReportRow {
  user: string;
  arn: string;
  password_enabled: string;
  password_last_changed: string;
  password_next_rotation: string;
  mfa_active: string;
  access_key_1_active: string;
  access_key_1_last_rotated: string;
  access_key_1_last_used_date: string;
  access_key_1_last_used_region: string;
  access_key_1_last_used_service: string;
  access_key_2_active: string;
  access_key_2_last_rotated: string;
  access_key_2_last_used_date: string;
  access_key_2_last_used_region: string;
  access_key_2_last_used_service: string;
}

interface PolicyRisk {
  severity: Severity;
  summary: string;
  detail: string;
}

interface ManagedPolicyAnalysis {
  policyName: string;
  policyArn: string;
  findings: PolicyRisk[];
}

@Injectable()
export class AwsAuditService {
  private readonly severityRank: Record<Severity, number> = {high: 3, medium: 2, low: 1};
  private readonly policyCache = new Map<string, Promise<ManagedPolicyAnalysis>>();
  private readonly activeScans = new Set<string>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly credentialService: AwsCredentialService
  ) {}

  async getProjectAuditReport(projectId: string, options: {detail: boolean}) {
    await this.ensureProjectExists(projectId);

    const credential = await this.prisma.projectAwsCredential.findUnique({where: {projectId}});
    const [currentScan, latestScan, latestSuccessfulScan, latestFailedScan] = await Promise.all([
      this.prisma.awsAuditScan.findFirst({
        where: {projectId, status: {in: ['PENDING', 'RUNNING']}},
        orderBy: {createdAt: 'desc'},
      }),
      this.prisma.awsAuditScan.findFirst({
        where: {projectId},
        orderBy: {createdAt: 'desc'},
      }),
      this.prisma.awsAuditScan.findFirst({
        where: {projectId, status: 'SUCCESS'},
        orderBy: {createdAt: 'desc'},
      }),
      this.prisma.awsAuditScan.findFirst({
        where: {projectId, status: 'FAILED'},
        orderBy: {createdAt: 'desc'},
      }),
    ]);

    return {
      projectId,
      hasSettings: Boolean(credential),
      currentScan: currentScan ? this.serializeScan(currentScan) : null,
      latestScan: latestScan ? this.serializeScan(latestScan) : null,
      latestSuccessfulScan: latestSuccessfulScan ? this.serializeScan(latestSuccessfulScan) : null,
      latestFailedScan: latestFailedScan ? this.serializeScan(latestFailedScan) : null,
      report: latestSuccessfulScan?.report
        ? options.detail
          ? latestSuccessfulScan.report
          : this.omitReportResources(latestSuccessfulScan.report as Record<string, any>)
        : null,
    };
  }

  async startProjectAuditScan(projectId: string) {
    const project = await this.ensureProjectExists(projectId);

    const credential = await this.prisma.projectAwsCredential.findUnique({where: {projectId}});
    if (!credential) {
      throw new BadRequestException(
        `Project ${project.name} does not have an AWS credential configured. Set it up in the AWS CREDENTIAL tab first.`
      );
    }

    const latestRunningScan = await this.prisma.awsAuditScan.findFirst({
      where: {projectId, status: {in: ['PENDING', 'RUNNING']}},
      orderBy: {createdAt: 'desc'},
    });

    if (latestRunningScan && this.activeScans.has(projectId)) {
      return {
        accepted: true,
        scan: this.serializeScan(latestRunningScan),
      };
    }

    if (latestRunningScan && !this.activeScans.has(projectId)) {
      await this.prisma.awsAuditScan.update({
        where: {id: latestRunningScan.id},
        data: {
          status: 'FAILED',
          errorMessage: latestRunningScan.errorMessage || 'Scan was interrupted before completion.',
          finishedAt: new Date(),
        },
      });
      await this.pruneFailedScans(projectId, latestRunningScan.id);
    }

    const scan = await this.prisma.awsAuditScan.create({
      data: {
        projectId,
        status: 'PENDING',
      },
    });

    this.activeScans.add(projectId);
    this.runAuditScanInBackground(projectId, scan.id).catch(() => {});

    return {
      accepted: true,
      scan: this.serializeScan(scan),
    };
  }

  private serializeScan(scan: any) {
    return {
      id: scan.id,
      projectId: scan.projectId,
      status: scan.status,
      errorMessage: scan.errorMessage,
      summary: scan.summary,
      hasReport: Boolean(scan.report),
      createdAt: scan.createdAt,
      updatedAt: scan.updatedAt,
      startedAt: scan.startedAt,
      finishedAt: scan.finishedAt,
    };
  }

  private omitReportResources(report: Record<string, any>) {
    return {
      ...report,
      resources: undefined,
    };
  }

  private async ensureProjectExists(projectId: string) {
    const project = await this.prisma.project.findUnique({where: {id: projectId}});
    if (!project) {
      throw new NotFoundException(`Project not found: ${projectId}`);
    }
    return project;
  }

  private async runAuditScanInBackground(projectId: string, scanId: string) {
    try {
      await this.prisma.awsAuditScan.update({
        where: {id: scanId},
        data: {
          status: 'RUNNING',
          startedAt: new Date(),
          errorMessage: null,
        },
      });

      const report = await this.buildAuditReport(projectId);
      await this.prisma.awsAuditScan.update({
        where: {id: scanId},
        data: {
          status: 'SUCCESS',
          summary: report.summary as any,
          report: report as any,
          finishedAt: new Date(),
          errorMessage: null,
        },
      });
    } catch (error: any) {
      await this.prisma.awsAuditScan.update({
        where: {id: scanId},
        data: {
          status: 'FAILED',
          errorMessage: this.getErrorMessage(error),
          finishedAt: new Date(),
        },
      });
      await this.pruneFailedScans(projectId, scanId);
    } finally {
      this.activeScans.delete(projectId);
    }
  }

  private async pruneFailedScans(projectId: string, keepId: string) {
    await this.prisma.awsAuditScan.deleteMany({
      where: {
        projectId,
        status: 'FAILED',
        id: {not: keepId},
      },
    });
  }

  private async buildAuditReport(projectId: string) {
    const project = await this.ensureProjectExists(projectId);

    const resolved = await this.credentialService.resolveProjectCredential(projectId);
    const credentials: AwsCredentials = {
      accessKeyId: resolved.accessKeyId,
      secretAccessKey: resolved.secretAccessKey,
    };
    const regions = (resolved.regions?.length ? resolved.regions : [resolved.defaultRegion || 'us-east-1'])
      .map(region => this.normalizeRegion(region));
    const primaryRegion = regions[0];
    const errors: AuditError[] = [];

    const identity = await getCallerIdentity(credentials, primaryRegion);

    const iamAudit = await this.captureStep(
      'iam',
      () => this.auditIam(credentials, primaryRegion),
      {findings: [], resources: {passwordPolicy: null, users: [], groups: [], roles: []}},
      errors
    );

    const s3Audit = await this.captureStep(
      's3',
      () => this.auditS3(credentials, primaryRegion),
      {findings: [], resources: []},
      errors
    );

    const regionalAudits = await Promise.all(
      regions.map(async region => ({
        region,
        ec2: await this.captureStep(
          'ec2',
          () => this.auditEc2Region(credentials, region),
          {findings: [], resources: {instances: [], securityGroups: []}},
          errors
        ),
        rds: await this.captureStep('rds', () => this.auditRdsRegion(credentials, region), {findings: [], resources: []}, errors),
      }))
    );

    const findings = [
      ...iamAudit.findings,
      ...s3Audit.findings,
      ...regionalAudits.flatMap(item => [...item.ec2.findings, ...item.rds.findings]),
    ].sort((left, right) => this.severityRank[right.severity] - this.severityRank[left.severity]);

    await this.prisma.projectAwsCredential.update({
      where: {projectId},
      data: {lastVerifiedAt: new Date()},
    });

    return {
      projectId,
      scannedAt: new Date().toISOString(),
      account: {
        projectName: project.name,
        configuredAwsAccountId: resolved.awsAccountId,
        discoveredAwsAccountId: identity.accountId,
        iamUserName: identity.iamUserName || resolved.iamUserName,
        callerArn: identity.arn,
        accessKeyId: resolved.accessKeyId,
        regions,
      },
      summary: {
        regionsScanned: regions,
        totalFindings: findings.length,
        high: findings.filter(item => item.severity === 'high').length,
        medium: findings.filter(item => item.severity === 'medium').length,
        low: findings.filter(item => item.severity === 'low').length,
        partialFailures: errors.length,
      },
      limitations: [
        'AWS does not expose IAM console passwords, EC2 instance login passwords, or RDS master passwords in plaintext via normal APIs.',
        'This report returns credential metadata, policy risk, network exposure, and secret references. Raw passwords are intentionally not returned.',
        'Findings are heuristic checks. Access Analyzer-style formal authorization proofs are not included in this implementation.',
      ],
      errors,
      findings,
      resources: {
        iam: iamAudit.resources,
        s3: s3Audit.resources,
        regional: regionalAudits.map(item => ({
          region: item.region,
          ec2: item.ec2.resources,
          rds: item.rds.resources,
        })),
      },
    };
  }

  private async auditIam(credentials: AwsCredentials, region: string) {
    const client = new IAMClient({region, credentials});
    const findings: AuditFinding[] = [];

    const passwordPolicy = await this.getPasswordPolicy(client);
    if (!passwordPolicy) {
      findings.push(
        this.createFinding({
          service: 'iam',
          severity: 'medium',
          resourceType: 'AwsAccount',
          resourceId: 'account-password-policy',
          title: 'IAM account password policy is not configured',
          detail: 'Console passwords do not appear to have an enforced account-wide policy.',
          recommendation: 'Configure an IAM account password policy with expiration and strong password requirements.',
          region,
        })
      );
    } else {
      if (!passwordPolicy.expirePasswords || !passwordPolicy.maxPasswordAge) {
        findings.push(
          this.createFinding({
            service: 'iam',
            severity: 'medium',
            resourceType: 'AwsAccount',
            resourceId: 'account-password-policy',
            title: 'IAM console passwords do not expire',
            detail: 'The account password policy does not enforce password expiration.',
            recommendation: 'Set `maxPasswordAge` to enforce password rotation for IAM console users.',
            region,
          })
        );
      }

      if ((passwordPolicy.minimumPasswordLength || 0) < 14) {
        findings.push(
          this.createFinding({
            service: 'iam',
            severity: 'low',
            resourceType: 'AwsAccount',
            resourceId: 'account-password-policy',
            title: 'IAM password minimum length is below 14 characters',
            detail: `Current minimum password length is ${passwordPolicy.minimumPasswordLength || 0}.`,
            recommendation: 'Increase the minimum password length to at least 14 characters.',
            region,
          })
        );
      }
    }

    const credentialReport = await this.getCredentialReportMap(client);
    const rootRow = credentialReport.get('<root_account>');
    if (rootRow) {
      if (this.isTruthy(rootRow.access_key_1_active) || this.isTruthy(rootRow.access_key_2_active)) {
        findings.push(
          this.createFinding({
            service: 'iam',
            severity: 'high',
            resourceType: 'RootAccount',
            resourceId: '<root_account>',
            title: 'Root account has active access keys',
            detail: 'The AWS root account still has active programmatic credentials.',
            recommendation: 'Remove root access keys and use IAM roles or IAM users instead.',
            region,
          })
        );
      }
      if (this.isTruthy(rootRow.password_enabled) && !this.isTruthy(rootRow.mfa_active)) {
        findings.push(
          this.createFinding({
            service: 'iam',
            severity: 'high',
            resourceType: 'RootAccount',
            resourceId: '<root_account>',
            title: 'Root account password is enabled without MFA',
            detail: 'Root console access appears enabled but MFA is not active.',
            recommendation: 'Enable MFA on the root account immediately.',
            region,
          })
        );
      }
    }

    const [users, groups, roles] = await Promise.all([
      this.listIamUsers(client),
      this.listIamGroups(client),
      this.listIamRoles(client),
    ]);

    const userResources = await Promise.all(
      users.map(async user => {
        const userName = user.UserName || user.Arn || 'unknown-user';
        const [attachedPolicies, inlinePolicies, userGroups] = await Promise.all([
          this.listAttachedUserPolicyAnalysis(client, userName),
          this.listInlineUserPolicyAnalysis(client, userName),
          this.listGroupsForUser(client, userName),
        ]);

        findings.push(...this.collectPolicyFindings('iam', 'IamUser', userName, attachedPolicies, region));
        findings.push(...this.collectPolicyFindings('iam', 'IamUser', userName, inlinePolicies, region));

        const reportRow = credentialReport.get(userName);
        findings.push(...this.collectCredentialFindings(userName, reportRow, passwordPolicy, region));

        return {
          userName,
          arn: user.Arn || null,
          createdAt: user.CreateDate || null,
          passwordEnabled: this.isTruthy(reportRow?.password_enabled),
          passwordLastChanged: this.toNullableStringDate(reportRow?.password_last_changed),
          passwordNextRotation: this.toNullableStringDate(reportRow?.password_next_rotation),
          mfaActive: this.isTruthy(reportRow?.mfa_active),
          groups: userGroups.map(group => group.GroupName).filter(Boolean),
          attachedPolicies: attachedPolicies.map(item => ({
            policyName: item.policyName,
            policyArn: item.policyArn,
            risks: item.findings,
          })),
          inlinePolicies: inlinePolicies,
          accessKeys: this.serializeCredentialReportAccessKeys(reportRow),
        };
      })
    );

    const groupResources = await Promise.all(
      groups.map(async group => {
        const groupName = group.GroupName || group.Arn || 'unknown-group';
        const [attachedPolicies, inlinePolicies] = await Promise.all([
          this.listAttachedGroupPolicyAnalysis(client, groupName),
          this.listInlineGroupPolicyAnalysis(client, groupName),
        ]);

        findings.push(...this.collectPolicyFindings('iam', 'IamGroup', groupName, attachedPolicies, region));
        findings.push(...this.collectPolicyFindings('iam', 'IamGroup', groupName, inlinePolicies, region));

        return {
          groupName,
          arn: group.Arn || null,
          createdAt: group.CreateDate || null,
          attachedPolicies: attachedPolicies.map(item => ({
            policyName: item.policyName,
            policyArn: item.policyArn,
            risks: item.findings,
          })),
          inlinePolicies: inlinePolicies,
        };
      })
    );

    const roleResources = await Promise.all(
      roles.map(async role => {
        const roleName = role.RoleName || role.Arn || 'unknown-role';
        const [attachedPolicies, inlinePolicies] = await Promise.all([
          this.listAttachedRolePolicyAnalysis(client, roleName),
          this.listInlineRolePolicyAnalysis(client, roleName),
        ]);

        findings.push(...this.collectPolicyFindings('iam', 'IamRole', roleName, attachedPolicies, region));
        findings.push(...this.collectPolicyFindings('iam', 'IamRole', roleName, inlinePolicies, region));

        return {
          roleName,
          arn: role.Arn || null,
          createdAt: role.CreateDate || null,
          lastUsedAt: role.RoleLastUsed?.LastUsedDate || null,
          attachedPolicies: attachedPolicies.map(item => ({
            policyName: item.policyName,
            policyArn: item.policyArn,
            risks: item.findings,
          })),
          inlinePolicies: inlinePolicies,
        };
      })
    );

    return {
      findings,
      resources: {
        passwordPolicy,
        users: userResources,
        groups: groupResources,
        roles: roleResources,
      },
    };
  }

  private async auditS3(credentials: AwsCredentials, region: string) {
    const client = new S3Client({region, credentials});
    const findings: AuditFinding[] = [];

    const response = await client.send(new ListBucketsCommand({}));
    const buckets = await Promise.all(
      (response.Buckets || []).map(async bucket => {
        const bucketName = bucket.Name || 'unknown-bucket';
        const bucketRegion = await this.resolveBucketRegion(client, bucketName);
        const bucketClient = new S3Client({
          region: bucketRegion,
          credentials,
        });

        const [publicAccessBlock, acl, policyStatus, encryption, versioning] = await Promise.all([
          this.safeBucketCall(() => bucketClient.send(new GetPublicAccessBlockCommand({Bucket: bucketName}))),
          this.safeBucketCall(() => bucketClient.send(new GetBucketAclCommand({Bucket: bucketName}))),
          this.safeBucketCall(() => bucketClient.send(new GetBucketPolicyStatusCommand({Bucket: bucketName}))),
          this.safeBucketCall(() => bucketClient.send(new GetBucketEncryptionCommand({Bucket: bucketName}))),
          this.safeBucketCall(() => bucketClient.send(new GetBucketVersioningCommand({Bucket: bucketName}))),
        ]);

        const publicAccessConfig = publicAccessBlock?.PublicAccessBlockConfiguration;
        if (!publicAccessConfig) {
          findings.push(
            this.createFinding({
              service: 's3',
              severity: 'medium',
              resourceType: 'S3Bucket',
              resourceId: bucketName,
              title: 'S3 bucket does not have Public Access Block configured',
              detail: `Bucket ${bucketName} is missing a Public Access Block configuration.`,
              recommendation: 'Enable all four Public Access Block settings unless the bucket must be public.',
              region: bucketRegion,
            })
          );
        } else if (
          !publicAccessConfig.BlockPublicAcls ||
          !publicAccessConfig.IgnorePublicAcls ||
          !publicAccessConfig.BlockPublicPolicy ||
          !publicAccessConfig.RestrictPublicBuckets
        ) {
          findings.push(
            this.createFinding({
              service: 's3',
              severity: 'high',
              resourceType: 'S3Bucket',
              resourceId: bucketName,
              title: 'S3 bucket Public Access Block is partially disabled',
              detail: `Bucket ${bucketName} does not block every public access path.`,
              recommendation: 'Enable every Public Access Block flag on the bucket and account level.',
              region: bucketRegion,
            })
          );
        }

        if (policyStatus?.PolicyStatus?.IsPublic) {
          findings.push(
            this.createFinding({
              service: 's3',
              severity: 'high',
              resourceType: 'S3Bucket',
              resourceId: bucketName,
              title: 'S3 bucket policy allows public access',
              detail: `Bucket policy on ${bucketName} is evaluated by AWS as public.`,
              recommendation: 'Remove public principals from the bucket policy or front the bucket with a private origin.',
              region: bucketRegion,
            })
          );
        }

        if (this.hasPublicAclGrant(acl)) {
          findings.push(
            this.createFinding({
              service: 's3',
              severity: 'high',
              resourceType: 'S3Bucket',
              resourceId: bucketName,
              title: 'S3 bucket ACL grants public access',
              detail: `Bucket ${bucketName} has ACL grants for AllUsers or AuthenticatedUsers.`,
              recommendation: 'Remove public ACL grants and rely on explicit private policies instead.',
              region: bucketRegion,
            })
          );
        }

        if (!encryption?.ServerSideEncryptionConfiguration?.Rules?.length) {
          findings.push(
            this.createFinding({
              service: 's3',
              severity: 'medium',
              resourceType: 'S3Bucket',
              resourceId: bucketName,
              title: 'S3 bucket default encryption is not enabled',
              detail: `Bucket ${bucketName} does not report a default server-side encryption rule.`,
              recommendation: 'Enable SSE-S3 or SSE-KMS for default bucket encryption.',
              region: bucketRegion,
            })
          );
        }

        if (versioning?.Status !== 'Enabled') {
          findings.push(
            this.createFinding({
              service: 's3',
              severity: 'low',
              resourceType: 'S3Bucket',
              resourceId: bucketName,
              title: 'S3 bucket versioning is not enabled',
              detail: `Bucket ${bucketName} has versioning status ${versioning?.Status || 'Disabled'}.`,
              recommendation: 'Enable versioning when the bucket stores important or mutable data.',
              region: bucketRegion,
            })
          );
        }

        return {
          name: bucketName,
          arn: bucketName ? `arn:aws:s3:::${bucketName}` : null,
          region: bucketRegion,
          createdAt: bucket.CreationDate || null,
          publicAccessBlock: publicAccessConfig || null,
          policyIsPublic: policyStatus?.PolicyStatus?.IsPublic || false,
          hasPublicAcl: this.hasPublicAclGrant(acl),
          encryptionEnabled: Boolean(encryption?.ServerSideEncryptionConfiguration?.Rules?.length),
          versioningStatus: versioning?.Status || 'Disabled',
        };
      })
    );

    return {
      findings,
      resources: buckets,
    };
  }

  private async auditEc2Region(credentials: AwsCredentials, region: string) {
    const client = new EC2Client({region, credentials});
    const findings: AuditFinding[] = [];
    const instances: any[] = [];
    const securityGroupIds = new Set<string>();

    let nextToken: string | undefined;
    do {
      const response = await client.send(new DescribeInstancesCommand({NextToken: nextToken}));
      for (const reservation of response.Reservations || []) {
        for (const instance of reservation.Instances || []) {
          const name = instance.Tags?.find(tag => tag.Key === 'Name')?.Value || instance.InstanceId || 'unknown-instance';
          const sgIds = (instance.SecurityGroups || []).map(group => group.GroupId).filter(Boolean) as string[];
          sgIds.forEach(id => securityGroupIds.add(id));

          instances.push({
            instanceId: instance.InstanceId || null,
            name,
            state: instance.State?.Name || null,
            instanceType: instance.InstanceType || null,
            publicIpAddress: instance.PublicIpAddress || null,
            privateIpAddress: instance.PrivateIpAddress || null,
            securityGroupIds: sgIds,
          });
        }
      }
      nextToken = response.NextToken;
    } while (nextToken);

    const securityGroups = await this.describeSecurityGroups(client, [...securityGroupIds]);
    for (const securityGroup of securityGroups) {
      findings.push(...this.collectSecurityGroupFindings(securityGroup, region));
    }

    return {
      findings,
      resources: {
        instances,
        securityGroups: securityGroups.map(group => ({
          groupId: group.GroupId || null,
          groupName: group.GroupName || null,
          description: group.Description || null,
          ingressRules: (group.IpPermissions || []).map(permission => ({
            protocol: permission.IpProtocol,
            fromPort: permission.FromPort ?? null,
            toPort: permission.ToPort ?? null,
            ipv4Ranges: (permission.IpRanges || []).map(item => item.CidrIp).filter(Boolean),
            ipv6Ranges: (permission.Ipv6Ranges || []).map(item => item.CidrIpv6).filter(Boolean),
          })),
        })),
      },
    };
  }

  private async auditRdsRegion(credentials: AwsCredentials, region: string) {
    const client = new RDSClient({region, credentials});
    const findings: AuditFinding[] = [];
    const instances: any[] = [];

    let marker: string | undefined;
    do {
      const response = await client.send(new DescribeDBInstancesCommand({Marker: marker}));
      for (const instance of response.DBInstances || []) {
        const identifier = instance.DBInstanceIdentifier || instance.DbiResourceId || 'unknown-rds';
        if (instance.PubliclyAccessible) {
          findings.push(
            this.createFinding({
              service: 'rds',
              severity: 'high',
              resourceType: 'RdsInstance',
              resourceId: identifier,
              title: 'RDS instance is publicly accessible',
              detail: `RDS instance ${identifier} allows public network access.`,
              recommendation: 'Move the database to private subnets and access it through application tiers or bastion hosts.',
              region,
            })
          );
        }

        if (!instance.StorageEncrypted) {
          findings.push(
            this.createFinding({
              service: 'rds',
              severity: 'high',
              resourceType: 'RdsInstance',
              resourceId: identifier,
              title: 'RDS storage encryption is disabled',
              detail: `RDS instance ${identifier} is not encrypted at rest.`,
              recommendation: 'Enable storage encryption on the database and snapshots.',
              region,
            })
          );
        }

        const hasManagedMasterSecret = Boolean(instance.MasterUserSecret?.SecretArn);
        if (!hasManagedMasterSecret) {
          findings.push(
            this.createFinding({
              service: 'rds',
              severity: 'medium',
              resourceType: 'RdsInstance',
              resourceId: identifier,
              title: 'RDS master password is not managed by AWS Secrets Manager',
              detail: `RDS instance ${identifier} does not report managed master user credentials.`,
              recommendation: 'Use AWS-managed master passwords or store credentials in Secrets Manager with rotation.',
              region,
            })
          );
        }

        instances.push({
          dbInstanceIdentifier: instance.DBInstanceIdentifier || null,
          dbiResourceId: instance.DbiResourceId || null,
          engine: instance.Engine || null,
          engineVersion: instance.EngineVersion || null,
          status: instance.DBInstanceStatus || null,
          publiclyAccessible: instance.PubliclyAccessible || false,
          storageEncrypted: instance.StorageEncrypted || false,
          deletionProtection: instance.DeletionProtection || false,
          masterUsername: instance.MasterUsername || null,
          manageMasterUserPassword: hasManagedMasterSecret,
          masterUserSecretArn: instance.MasterUserSecret?.SecretArn || null,
          multiAz: instance.MultiAZ || false,
        });
      }
      marker = response.Marker;
    } while (marker);

    return {
      findings,
      resources: instances,
    };
  }

  private async describeSecurityGroups(client: EC2Client, securityGroupIds: string[]) {
    if (!securityGroupIds.length) {
      return [];
    }

    const groups: SecurityGroup[] = [];
    for (let index = 0; index < securityGroupIds.length; index += 100) {
      const chunk = securityGroupIds.slice(index, index + 100);
      const response = await client.send(new DescribeSecurityGroupsCommand({GroupIds: chunk}));
      groups.push(...(response.SecurityGroups || []));
    }
    return groups;
  }

  private collectSecurityGroupFindings(group: SecurityGroup, region: string) {
    const findings: AuditFinding[] = [];
    const groupId = group.GroupId || group.GroupName || 'unknown-security-group';

    for (const permission of group.IpPermissions || []) {
      const ipv4Public = (permission.IpRanges || []).some(item => item.CidrIp === '0.0.0.0/0');
      const ipv6Public = (permission.Ipv6Ranges || []).some(item => item.CidrIpv6 === '::/0');
      if (!ipv4Public && !ipv6Public) {
        continue;
      }

      if (permission.IpProtocol === '-1') {
        findings.push(
          this.createFinding({
            service: 'ec2',
            severity: 'high',
            resourceType: 'SecurityGroup',
            resourceId: groupId,
            title: 'Security group allows all traffic from the internet',
            detail: `Security group ${groupId} allows every protocol from a public CIDR range.`,
            recommendation: 'Restrict the rule to trusted CIDRs and the minimum required ports.',
            region,
          })
        );
        continue;
      }

      const sensitivePorts = [22, 3389, 3306, 5432, 6379, 27017, 9200];
      const fromPort = permission.FromPort ?? -1;
      const toPort = permission.ToPort ?? -1;
      const exposedSensitivePorts = sensitivePorts.filter(port => port >= fromPort && port <= toPort);
      if (exposedSensitivePorts.length) {
        findings.push(
          this.createFinding({
            service: 'ec2',
            severity: 'high',
            resourceType: 'SecurityGroup',
            resourceId: groupId,
            title: 'Security group exposes sensitive ports to the internet',
            detail: `Security group ${groupId} exposes public ingress on ports ${exposedSensitivePorts.join(', ')}.`,
            recommendation: 'Restrict SSH/RDP/database ports to trusted internal CIDRs or VPN ingress.',
            region,
          })
        );
      } else {
        findings.push(
          this.createFinding({
            service: 'ec2',
            severity: 'medium',
            resourceType: 'SecurityGroup',
            resourceId: groupId,
            title: 'Security group has public ingress',
            detail: `Security group ${groupId} allows ingress from a public CIDR range.`,
            recommendation: 'Review whether the public ingress rule is required.',
            region,
          })
        );
      }
    }

    return findings;
  }

  private async getPasswordPolicy(client: IAMClient) {
    try {
      const response = await client.send(new GetAccountPasswordPolicyCommand({}));
      const policy = response.PasswordPolicy;
      if (!policy) {
        return null;
      }
      return {
        minimumPasswordLength: policy.MinimumPasswordLength || 0,
        requireSymbols: policy.RequireSymbols || false,
        requireNumbers: policy.RequireNumbers || false,
        requireUppercaseCharacters: policy.RequireUppercaseCharacters || false,
        requireLowercaseCharacters: policy.RequireLowercaseCharacters || false,
        allowUsersToChangePassword: policy.AllowUsersToChangePassword || false,
        expirePasswords: policy.ExpirePasswords || false,
        maxPasswordAge: policy.MaxPasswordAge || null,
        passwordReusePrevention: policy.PasswordReusePrevention || null,
        hardExpiry: policy.HardExpiry || false,
      };
    } catch (error: any) {
      if (error?.name === 'NoSuchEntityException') {
        return null;
      }
      throw error;
    }
  }

  private async getCredentialReportMap(client: IAMClient) {
    await client.send(new GenerateCredentialReportCommand({}));

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const response = await client.send(new GetCredentialReportCommand({}));
      if (response.Content) {
        const csv = Buffer.from(response.Content).toString('utf8');
        const rows = this.parseCsv(csv);
        const map = new Map<string, CredentialReportRow>();
        for (const row of rows) {
          if (row.user) {
            map.set(row.user, row as unknown as CredentialReportRow);
          }
        }
        return map;
      }
      await this.sleep(500);
    }

    return new Map<string, CredentialReportRow>();
  }

  private async listIamUsers(client: IAMClient) {
    const items: any[] = [];
    let marker: string | undefined;

    do {
      const response = await client.send(new ListUsersCommand({Marker: marker, MaxItems: 1000}));
      items.push(...(response.Users || []));
      marker = response.IsTruncated ? response.Marker : undefined;
    } while (marker);

    return items;
  }

  private async listIamGroups(client: IAMClient) {
    const items: any[] = [];
    let marker: string | undefined;

    do {
      const response = await client.send(new ListGroupsCommand({Marker: marker, MaxItems: 1000}));
      items.push(...(response.Groups || []));
      marker = response.IsTruncated ? response.Marker : undefined;
    } while (marker);

    return items;
  }

  private async listIamRoles(client: IAMClient) {
    const items: any[] = [];
    let marker: string | undefined;

    do {
      const response = await client.send(new ListRolesCommand({Marker: marker, MaxItems: 1000}));
      items.push(...(response.Roles || []));
      marker = response.IsTruncated ? response.Marker : undefined;
    } while (marker);

    return items;
  }

  private async listGroupsForUser(client: IAMClient, userName: string) {
    const items: any[] = [];
    let marker: string | undefined;

    do {
      const response = await client.send(new ListGroupsForUserCommand({UserName: userName, Marker: marker, MaxItems: 1000}));
      items.push(...(response.Groups || []));
      marker = response.IsTruncated ? response.Marker : undefined;
    } while (marker);

    return items;
  }

  private async listAttachedUserPolicyAnalysis(client: IAMClient, userName: string) {
    const analyses: ManagedPolicyAnalysis[] = [];
    let marker: string | undefined;

    do {
      const response = await client.send(
        new ListAttachedUserPoliciesCommand({UserName: userName, Marker: marker, MaxItems: 1000})
      );
      for (const policy of response.AttachedPolicies || []) {
        if (!policy.PolicyArn || !policy.PolicyName) {
          continue;
        }
        analyses.push(await this.getManagedPolicyAnalysis(client, policy.PolicyArn, policy.PolicyName));
      }
      marker = response.IsTruncated ? response.Marker : undefined;
    } while (marker);

    return analyses;
  }

  private async listInlineUserPolicyAnalysis(client: IAMClient, userName: string) {
    const analyses: ManagedPolicyAnalysis[] = [];
    let marker: string | undefined;

    do {
      const response = await client.send(new ListUserPoliciesCommand({UserName: userName, Marker: marker, MaxItems: 1000}));
      for (const policyName of response.PolicyNames || []) {
        const policy = await client.send(new GetUserPolicyCommand({UserName: userName, PolicyName: policyName}));
        analyses.push({
          policyName,
          policyArn: `inline:user:${userName}:${policyName}`,
          findings: this.evaluatePolicyDocument(policy.PolicyDocument),
        });
      }
      marker = response.IsTruncated ? response.Marker : undefined;
    } while (marker);

    return analyses;
  }

  private async listAttachedGroupPolicyAnalysis(client: IAMClient, groupName: string) {
    const analyses: ManagedPolicyAnalysis[] = [];
    let marker: string | undefined;

    do {
      const response = await client.send(
        new ListAttachedGroupPoliciesCommand({GroupName: groupName, Marker: marker, MaxItems: 1000})
      );
      for (const policy of response.AttachedPolicies || []) {
        if (!policy.PolicyArn || !policy.PolicyName) {
          continue;
        }
        analyses.push(await this.getManagedPolicyAnalysis(client, policy.PolicyArn, policy.PolicyName));
      }
      marker = response.IsTruncated ? response.Marker : undefined;
    } while (marker);

    return analyses;
  }

  private async listInlineGroupPolicyAnalysis(client: IAMClient, groupName: string) {
    const analyses: ManagedPolicyAnalysis[] = [];
    let marker: string | undefined;

    do {
      const response = await client.send(new ListGroupPoliciesCommand({GroupName: groupName, Marker: marker, MaxItems: 1000}));
      for (const policyName of response.PolicyNames || []) {
        const policy = await client.send(new GetGroupPolicyCommand({GroupName: groupName, PolicyName: policyName}));
        analyses.push({
          policyName,
          policyArn: `inline:group:${groupName}:${policyName}`,
          findings: this.evaluatePolicyDocument(policy.PolicyDocument),
        });
      }
      marker = response.IsTruncated ? response.Marker : undefined;
    } while (marker);

    return analyses;
  }

  private async listAttachedRolePolicyAnalysis(client: IAMClient, roleName: string) {
    const analyses: ManagedPolicyAnalysis[] = [];
    let marker: string | undefined;

    do {
      const response = await client.send(
        new ListAttachedRolePoliciesCommand({RoleName: roleName, Marker: marker, MaxItems: 1000})
      );
      for (const policy of response.AttachedPolicies || []) {
        if (!policy.PolicyArn || !policy.PolicyName) {
          continue;
        }
        analyses.push(await this.getManagedPolicyAnalysis(client, policy.PolicyArn, policy.PolicyName));
      }
      marker = response.IsTruncated ? response.Marker : undefined;
    } while (marker);

    return analyses;
  }

  private async listInlineRolePolicyAnalysis(client: IAMClient, roleName: string) {
    const analyses: ManagedPolicyAnalysis[] = [];
    let marker: string | undefined;

    do {
      const response = await client.send(new ListRolePoliciesCommand({RoleName: roleName, Marker: marker, MaxItems: 1000}));
      for (const policyName of response.PolicyNames || []) {
        const policy = await client.send(new GetRolePolicyCommand({RoleName: roleName, PolicyName: policyName}));
        analyses.push({
          policyName,
          policyArn: `inline:role:${roleName}:${policyName}`,
          findings: this.evaluatePolicyDocument(policy.PolicyDocument),
        });
      }
      marker = response.IsTruncated ? response.Marker : undefined;
    } while (marker);

    return analyses;
  }

  private async getManagedPolicyAnalysis(client: IAMClient, policyArn: string, policyName: string) {
    if (!this.policyCache.has(policyArn)) {
      this.policyCache.set(
        policyArn,
        (async () => {
          const policy = await client.send(new GetPolicyCommand({PolicyArn: policyArn}));
          const defaultVersionId = policy.Policy?.DefaultVersionId;
          if (!defaultVersionId) {
            return {policyArn, policyName, findings: []};
          }
          const version = await client.send(
            new GetPolicyVersionCommand({
              PolicyArn: policyArn,
              VersionId: defaultVersionId,
            })
          );
          return {
            policyArn,
            policyName,
            findings: this.evaluatePolicyDocument(version.PolicyVersion?.Document),
          };
        })()
      );
    }

    return await this.policyCache.get(policyArn)!;
  }

  private evaluatePolicyDocument(document: unknown): PolicyRisk[] {
    const parsed = this.parsePolicyDocument(document);
    if (!parsed || !parsed.Statement) {
      return [];
    }

    const statements = Array.isArray(parsed.Statement) ? parsed.Statement : [parsed.Statement];
    const findings: PolicyRisk[] = [];

    for (const statement of statements) {
      if (!statement || statement.Effect !== 'Allow') {
        continue;
      }

      const actions = this.toArray(statement.Action);
      const notActions = this.toArray(statement.NotAction);
      const resources = this.toArray(statement.Resource);
      const hasGlobalResource = resources.includes('*');

      if (notActions.length) {
        findings.push({
          severity: 'high',
          summary: 'Allow statement uses NotAction',
          detail: 'An Allow + NotAction statement often grants very broad permissions and should be reviewed manually.',
        });
      }

      if (actions.includes('*') && hasGlobalResource) {
        findings.push({
          severity: 'high',
          summary: 'Policy allows * on *',
          detail: 'The policy grants unrestricted access across all services and resources.',
        });
      }

      const serviceWildcards = actions.filter(action => typeof action === 'string' && action.endsWith(':*'));
      for (const action of serviceWildcards) {
        const serviceName = action.split(':')[0];
        const severity: Severity = ['iam', 'sts', 'kms', 'organizations'].includes(serviceName) ? 'high' : 'medium';
        if (hasGlobalResource) {
          findings.push({
            severity,
            summary: `Policy grants ${action} on *`,
            detail: `The policy grants broad ${serviceName.toUpperCase()} access across all resources.`,
          });
        }
      }

      const sensitiveActions = ['iam:PassRole', 'sts:AssumeRole', 'kms:Decrypt', 'secretsmanager:GetSecretValue'];
      const exposedSensitiveActions = actions.filter(action => sensitiveActions.includes(action));
      if (exposedSensitiveActions.length && hasGlobalResource) {
        findings.push({
          severity: 'high',
          summary: `Policy grants sensitive actions on *`,
          detail: `Sensitive actions ${exposedSensitiveActions.join(', ')} are allowed on every resource.`,
        });
      }
    }

    return this.deduplicatePolicyRisks(findings);
  }

  private collectPolicyFindings(
    service: AuditFinding['service'],
    resourceType: string,
    resourceId: string,
    policies: ManagedPolicyAnalysis[],
    region: string
  ) {
    return policies.flatMap(policy =>
      policy.findings.map(finding =>
        this.createFinding({
          service,
          severity: finding.severity,
          resourceType,
          resourceId,
          title: `${policy.policyName}: ${finding.summary}`,
          detail: finding.detail,
          recommendation: 'Replace wildcard permissions with least-privilege actions and resource ARNs.',
          region,
        })
      )
    );
  }

  private collectCredentialFindings(
    userName: string,
    row: CredentialReportRow | undefined,
    passwordPolicy: {maxPasswordAge: number | null} | null,
    region: string
  ) {
    const findings: AuditFinding[] = [];
    if (!row) {
      return findings;
    }

    if (this.isTruthy(row.password_enabled) && !this.isTruthy(row.mfa_active)) {
      findings.push(
        this.createFinding({
          service: 'iam',
          severity: 'medium',
          resourceType: 'IamUser',
          resourceId: userName,
          title: 'IAM console user does not have MFA enabled',
          detail: `User ${userName} has console password access without MFA.`,
          recommendation: 'Require MFA for every console-capable IAM user.',
          region,
        })
      );
    }

    const passwordNextRotation = this.toDate(row.password_next_rotation);
    if (this.isTruthy(row.password_enabled) && passwordNextRotation && passwordNextRotation.getTime() < Date.now()) {
      findings.push(
        this.createFinding({
          service: 'iam',
          severity: 'high',
          resourceType: 'IamUser',
          resourceId: userName,
          title: 'IAM user password is past the next rotation date',
          detail: `User ${userName} password rotation deadline was ${passwordNextRotation.toISOString()}.`,
          recommendation: 'Reset the user password and review whether the account still needs console access.',
          region,
        })
      );
    } else if (
      this.isTruthy(row.password_enabled) &&
      passwordPolicy?.maxPasswordAge &&
      !passwordNextRotation
    ) {
      findings.push(
        this.createFinding({
          service: 'iam',
          severity: 'medium',
          resourceType: 'IamUser',
          resourceId: userName,
          title: 'IAM user password rotation status is unclear',
          detail: `User ${userName} has a console password but no next rotation date was derived from the credential report.`,
          recommendation: 'Review the user login profile and force a password reset if needed.',
          region,
        })
      );
    }

    const accessKeys = this.serializeCredentialReportAccessKeys(row);
    const activeAccessKeys = accessKeys.filter(item => item.active);
    if (activeAccessKeys.length > 1) {
      findings.push(
        this.createFinding({
          service: 'iam',
          severity: 'low',
          resourceType: 'IamUser',
          resourceId: userName,
          title: 'IAM user has multiple active access keys',
          detail: `User ${userName} currently has ${activeAccessKeys.length} active access keys.`,
          recommendation: 'Rotate and remove older access keys when they are no longer needed.',
          region,
        })
      );
    }

    for (const accessKey of activeAccessKeys) {
      if (accessKey.lastRotatedAt && this.daysSince(accessKey.lastRotatedAt) > 90) {
        findings.push(
          this.createFinding({
            service: 'iam',
            severity: 'medium',
            resourceType: 'IamAccessKey',
            resourceId: `${userName}:${accessKey.slot}`,
            title: 'IAM access key is older than 90 days',
            detail: `Access key slot ${accessKey.slot} for user ${userName} was last rotated on ${accessKey.lastRotatedAt}.`,
            recommendation: 'Rotate long-lived access keys or replace them with short-lived IAM roles.',
            region,
          })
        );
      }

      if (!accessKey.lastUsedAt) {
        findings.push(
          this.createFinding({
            service: 'iam',
            severity: 'low',
            resourceType: 'IamAccessKey',
            resourceId: `${userName}:${accessKey.slot}`,
            title: 'IAM access key has no recorded usage',
            detail: `Access key slot ${accessKey.slot} for user ${userName} does not show a last-used timestamp.`,
            recommendation: 'Delete the key if it is no longer required.',
            region,
          })
        );
      }
    }

    return findings;
  }

  private serializeCredentialReportAccessKeys(row?: CredentialReportRow) {
    if (!row) {
      return [];
    }

    return [
      {
        slot: 1,
        active: this.isTruthy(row.access_key_1_active),
        lastRotatedAt: this.toNullableStringDate(row.access_key_1_last_rotated),
        lastUsedAt: this.toNullableStringDate(row.access_key_1_last_used_date),
        lastUsedRegion: this.normalizeNullableString(row.access_key_1_last_used_region),
        lastUsedService: this.normalizeNullableString(row.access_key_1_last_used_service),
      },
      {
        slot: 2,
        active: this.isTruthy(row.access_key_2_active),
        lastRotatedAt: this.toNullableStringDate(row.access_key_2_last_rotated),
        lastUsedAt: this.toNullableStringDate(row.access_key_2_last_used_date),
        lastUsedRegion: this.normalizeNullableString(row.access_key_2_last_used_region),
        lastUsedService: this.normalizeNullableString(row.access_key_2_last_used_service),
      },
    ];
  }

  private async resolveBucketRegion(client: S3Client, bucketName: string) {
    const response = await client.send(new GetBucketLocationCommand({Bucket: bucketName}));
    if (!response.LocationConstraint) {
      return 'us-east-1';
    }
    return String(response.LocationConstraint);
  }

  private async safeBucketCall<T>(fn: () => Promise<T>) {
    try {
      return await fn();
    } catch (error: any) {
      if (
        error?.name === 'NoSuchPublicAccessBlockConfiguration' ||
        error?.name === 'ServerSideEncryptionConfigurationNotFoundError' ||
        error?.name === 'NoSuchBucketPolicy' ||
        error?.name === 'NoSuchBucket'
      ) {
        return null;
      }
      if (error?.$metadata?.httpStatusCode === 404) {
        return null;
      }
      throw error;
    }
  }

  private hasPublicAclGrant(acl: any) {
    const grants = acl?.Grants || [];
    return grants.some((grant: any) => {
      const uri = grant.Grantee?.URI;
      return (
        uri === 'http://acs.amazonaws.com/groups/global/AllUsers' ||
        uri === 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
      );
    });
  }

  private parsePolicyDocument(document: unknown) {
    if (!document) {
      return null;
    }
    if (typeof document === 'object') {
      return document as Record<string, any>;
    }
    if (typeof document !== 'string') {
      return null;
    }
    try {
      return JSON.parse(document);
    } catch {
      try {
        return JSON.parse(decodeURIComponent(document));
      } catch {
        return null;
      }
    }
  }

  private toArray(value: unknown) {
    if (!value) {
      return [];
    }
    return Array.isArray(value) ? value : [value];
  }

  private deduplicatePolicyRisks(findings: PolicyRisk[]) {
    const seen = new Set<string>();
    return findings.filter(finding => {
      const key = `${finding.severity}:${finding.summary}:${finding.detail}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  private parseCsv(csv: string) {
    const lines = csv.split(/\r?\n/).filter(Boolean);
    if (lines.length < 2) {
      return [];
    }

    const headers = this.parseCsvLine(lines[0]);
    return lines.slice(1).map(line => {
      const values = this.parseCsvLine(line);
      return headers.reduce<Record<string, string>>((accumulator, header, index) => {
        accumulator[header] = values[index] || '';
        return accumulator;
      }, {});
    });
  }

  private parseCsvLine(line: string) {
    const values: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let index = 0; index < line.length; index += 1) {
      const character = line[index];
      const nextCharacter = line[index + 1];

      if (character === '"' && inQuotes && nextCharacter === '"') {
        current += '"';
        index += 1;
        continue;
      }

      if (character === '"') {
        inQuotes = !inQuotes;
        continue;
      }

      if (character === ',' && !inQuotes) {
        values.push(current);
        current = '';
        continue;
      }

      current += character;
    }

    values.push(current);
    return values;
  }

  private toDate(value?: string | null) {
    if (!value || ['N/A', 'no_information', 'not_supported'].includes(value)) {
      return null;
    }
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  private toNullableStringDate(value?: string | null) {
    return this.toDate(value)?.toISOString() || null;
  }

  private normalizeNullableString(value?: string | null) {
    if (!value || ['N/A', 'no_information', 'not_supported'].includes(value)) {
      return null;
    }
    return value;
  }

  private isTruthy(value?: string | null) {
    return value === 'true';
  }

  private daysSince(dateIsoString: string) {
    const timestamp = new Date(dateIsoString).getTime();
    return Math.floor((Date.now() - timestamp) / (1000 * 60 * 60 * 24));
  }

  private createFinding(args: AuditFinding) {
    return args;
  }

  private async captureStep<T>(
    service: AuditError['service'],
    fn: () => Promise<T>,
    fallback: T,
    errors: AuditError[]
  ) {
    try {
      return await fn();
    } catch (error: any) {
      errors.push({
        service,
        message: this.getErrorMessage(error),
      });
      return fallback;
    }
  }

  private getErrorMessage(error: any) {
    return error?.message || error?.name || 'Unknown AWS audit error';
  }

  private normalizeRegion(region: string) {
    return region.trim().toLowerCase();
  }

  private sleep(milliseconds: number) {
    return new Promise(resolve => setTimeout(resolve, milliseconds));
  }
}

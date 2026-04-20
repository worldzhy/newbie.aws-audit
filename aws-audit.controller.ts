import {Controller, Get, Param, Post, Query} from '@nestjs/common';
import {AwsAuditService} from './aws-audit.service';
import {GetAwsAuditReportDto} from './aws-audit.dto';

@Controller('aws-audit/projects')
export class AwsAuditController {
  constructor(private readonly awsAuditService: AwsAuditService) {}

  @Get(':projectId/report')
  async getProjectReport(@Param('projectId') projectId: string, @Query() query: GetAwsAuditReportDto): Promise<any> {
    return await this.awsAuditService.getProjectAuditReport(projectId, {
      detail: query.detail !== 'false',
    });
  }

  @Post(':projectId/scan')
  async startProjectScan(@Param('projectId') projectId: string): Promise<any> {
    return await this.awsAuditService.startProjectAuditScan(projectId);
  }
}

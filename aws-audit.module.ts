import {Global, Module} from '@nestjs/common';
import {AwsAuditController} from './aws-audit.controller';
import {AwsAuditService} from './aws-audit.service';

@Global()
@Module({
  controllers: [AwsAuditController],
  providers: [AwsAuditService],
  exports: [AwsAuditService],
})
export class AwsAuditModule {}

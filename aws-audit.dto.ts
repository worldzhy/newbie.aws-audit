import {ApiPropertyOptional} from '@nestjs/swagger';
import {IsOptional, IsString} from 'class-validator';

export class GetAwsAuditReportDto {
  @ApiPropertyOptional({
    description: 'When true, include full resource inventory. When false, only returns summary and findings.',
    default: true,
  })
  @IsOptional()
  @IsString()
  detail?: string;
}

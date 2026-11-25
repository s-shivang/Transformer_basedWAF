import {
  IsArray,
  IsBoolean,
  IsEnum,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { WafAction } from '../../domain/security-event.types';

export class IngestSecurityEventDto {
  @ApiProperty({ example: '85fbb918-6f68-45b9-9a2e-4b476db57f44' })
  @IsString()
  @IsNotEmpty()
  tenantId: string;

  @ApiPropertyOptional({ example: 'c4e427d1-e945-42f0-b997-7f99990b79fa' })
  @IsOptional()
  @IsString()
  siteId?: string;

  @ApiProperty({ example: 'req-prod-001' })
  @IsString()
  @IsNotEmpty()
  requestId: string;

  @ApiPropertyOptional({ example: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' })
  @IsOptional()
  @IsString()
  clientIpHash?: string;

  @ApiProperty({ example: 'POST' })
  @IsString()
  @IsNotEmpty()
  method: string;

  @ApiProperty({ example: '/api/v1/login' })
  @IsString()
  @IsNotEmpty()
  path: string;

  @ApiProperty({ enum: WafAction, example: WafAction.BLOCK })
  @IsEnum(WafAction)
  action: WafAction;

  @ApiPropertyOptional({ enum: WafAction, example: WafAction.BLOCK })
  @IsOptional()
  @IsEnum(WafAction)
  wouldAction?: WafAction;

  @ApiPropertyOptional({ example: 'ML confidence score exceeded block threshold (0.912 >= 0.85)' })
  @IsOptional()
  @IsString()
  reason?: string;

  @ApiPropertyOptional({ example: 0.912 })
  @IsOptional()
  @IsNumber()
  riskScore?: number;

  @ApiPropertyOptional({ example: 'ml_layer2' })
  @IsOptional()
  @IsString()
  stageUsed?: string;

  @ApiPropertyOptional({ example: [] })
  @IsOptional()
  @IsArray()
  ruleMatches?: any[];

  @ApiPropertyOptional({ example: [] })
  @IsOptional()
  @IsArray()
  anomalyFlags?: any[];

  @ApiPropertyOptional({ example: false })
  @IsOptional()
  @IsBoolean()
  degradedMode?: boolean;

  @ApiPropertyOptional({ example: 'v1_0' })
  @IsOptional()
  @IsString()
  modelVersion?: string;

  @ApiPropertyOptional({ example: 1 })
  @IsOptional()
  @IsNumber()
  policyVersion?: number;

  @ApiPropertyOptional({ example: 4.8 })
  @IsOptional()
  @IsNumber()
  latencyMs?: number;

  @ApiPropertyOptional({ example: { headers: { host: 'api.acme.com' } } })
  @IsOptional()
  redactedRequest?: any;

  @ApiPropertyOptional({ example: '2026-11-25T12:00:00.000Z' })
  @IsOptional()
  @IsString()
  createdAt?: string;
}

export class BatchIngestEventsDto {
  @ApiProperty({ type: [IngestSecurityEventDto] })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => IngestSecurityEventDto)
  events: IngestSecurityEventDto[];
}

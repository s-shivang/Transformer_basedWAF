import {
  IsBoolean,
  IsEnum,
  IsNumber,
  IsOptional,
  IsString,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiPropertyOptional } from '@nestjs/swagger';
import { WafAction } from '../../domain/security-event.types';

export class QuerySecurityEventsDto {
  @ApiPropertyOptional({ example: 'c4e427d1-e945-42f0-b997-7f99990b79fa' })
  @IsOptional()
  @IsString()
  siteId?: string;

  @ApiPropertyOptional({ enum: WafAction })
  @IsOptional()
  @IsEnum(WafAction)
  action?: WafAction;

  @ApiPropertyOptional({ example: 0.50 })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  minRiskScore?: number;

  @ApiPropertyOptional({ example: 1.0 })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  maxRiskScore?: number;

  @ApiPropertyOptional({ example: 'ml_layer2' })
  @IsOptional()
  @IsString()
  stageUsed?: string;

  @ApiPropertyOptional({ example: false })
  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  degradedMode?: boolean;

  @ApiPropertyOptional({ example: '/login' })
  @IsOptional()
  @IsString()
  pathContains?: string;

  @ApiPropertyOptional({ example: '2026-11-01T00:00:00.000Z' })
  @IsOptional()
  @IsString()
  from?: string;

  @ApiPropertyOptional({ example: '2026-11-30T23:59:59.000Z' })
  @IsOptional()
  @IsString()
  to?: string;

  @ApiPropertyOptional({ default: 1 })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  page?: number;

  @ApiPropertyOptional({ default: 20 })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  limit?: number;
}

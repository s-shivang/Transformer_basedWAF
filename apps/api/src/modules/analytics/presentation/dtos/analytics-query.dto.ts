import { IsEnum, IsNumber, IsOptional, IsString } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiPropertyOptional } from '@nestjs/swagger';

export enum AnalyticsWindow {
  HOURS_24 = '24h',
  DAYS_7 = '7d',
  DAYS_30 = '30d',
}

export class QueryAnalyticsDto {
  @ApiPropertyOptional({ example: 'c4e427d1-e945-42f0-b997-7f99990b79fa' })
  @IsOptional()
  @IsString()
  siteId?: string;

  @ApiPropertyOptional({ enum: AnalyticsWindow, default: AnalyticsWindow.HOURS_24 })
  @IsOptional()
  @IsEnum(AnalyticsWindow)
  window?: AnalyticsWindow = AnalyticsWindow.HOURS_24;

  @ApiPropertyOptional({ default: 10 })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  limit?: number;
}

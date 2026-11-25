import {
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
import { WafMode, MlFailureMode } from '../../domain/waf-policy.entity';

export class ScopedExclusionDto {
  @ApiProperty({ example: '/api/v1/webhooks' })
  @IsString()
  @IsNotEmpty()
  pathPrefix: string;

  @ApiPropertyOptional({ example: 'payload' })
  @IsOptional()
  @IsString()
  parameterName?: string;

  @ApiProperty({ example: 'Third-party JSON payload contains encoded binary strings' })
  @IsString()
  @IsNotEmpty()
  reason: string;

  @ApiPropertyOptional({ default: true })
  @IsOptional()
  @IsBoolean()
  skipMl?: boolean;

  @ApiPropertyOptional({ default: false })
  @IsOptional()
  @IsBoolean()
  skipRules?: boolean;
}

export class UpdateWafPolicyDto {
  @ApiPropertyOptional({ example: 'Updated Production Policy' })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({ enum: WafMode, example: WafMode.BLOCKING })
  @IsOptional()
  @IsEnum(WafMode)
  mode?: WafMode;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  mlEnabled?: boolean;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  rulesEnabled?: boolean;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  challengeEnabled?: boolean;

  @ApiPropertyOptional({ example: 0.05 })
  @IsOptional()
  @IsNumber()
  monitorThreshold?: number;

  @ApiPropertyOptional({ example: 0.50 })
  @IsOptional()
  @IsNumber()
  challengeThreshold?: number;

  @ApiPropertyOptional({ example: 0.85 })
  @IsOptional()
  @IsNumber()
  blockThreshold?: number;

  @ApiPropertyOptional({ enum: MlFailureMode, example: MlFailureMode.FAIL_OPEN })
  @IsOptional()
  @IsEnum(MlFailureMode)
  mlFailureMode?: MlFailureMode;

  @ApiPropertyOptional({ type: [ScopedExclusionDto] })
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => ScopedExclusionDto)
  exclusions?: ScopedExclusionDto[];
}


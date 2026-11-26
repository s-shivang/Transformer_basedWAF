import {
  IsEnum,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { FeedbackLabel, FeedbackReviewStatus } from '../../domain/security-event.types';

export class SubmitFeedbackDto {
  @ApiProperty({ enum: FeedbackLabel, example: FeedbackLabel.FALSE_POSITIVE })
  @IsEnum(FeedbackLabel)
  @IsNotEmpty()
  label: FeedbackLabel;

  @ApiPropertyOptional({ example: 'Legitimate SQL-like string inside analytics search box' })
  @IsOptional()
  @IsString()
  notes?: string;
}

export class ReviewFeedbackDto {
  @ApiProperty({ enum: [FeedbackReviewStatus.APPROVED, FeedbackReviewStatus.REJECTED], example: FeedbackReviewStatus.APPROVED })
  @IsEnum(FeedbackReviewStatus)
  @IsNotEmpty()
  status: FeedbackReviewStatus;

  @ApiPropertyOptional({ example: 'Verified benign search pattern, queued for offline fine-tuning dataset' })
  @IsOptional()
  @IsString()
  reviewNotes?: string;
}

export class QueryFeedbackDto {
  @ApiPropertyOptional({ example: 'c4e427d1-e945-42f0-b997-7f99990b79fa' })
  @IsOptional()
  @IsString()
  siteId?: string;

  @ApiPropertyOptional({ enum: FeedbackReviewStatus })
  @IsOptional()
  @IsEnum(FeedbackReviewStatus)
  reviewStatus?: FeedbackReviewStatus;

  /**
   * Alias for reviewStatus to support frontend queries using ?status=
   */
  @ApiPropertyOptional({ enum: FeedbackReviewStatus })
  @IsOptional()
  @IsEnum(FeedbackReviewStatus)
  status?: FeedbackReviewStatus;

  @ApiPropertyOptional({ enum: FeedbackLabel })
  @IsOptional()
  @IsEnum(FeedbackLabel)
  label?: FeedbackLabel;

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

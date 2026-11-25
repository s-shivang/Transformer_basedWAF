import { IsArray, IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateWebhookDto {
  @ApiProperty({ description: 'Display name for the webhook endpoint', example: 'SOC PagerDuty Alerts' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ description: 'HTTPS Webhook URL target', example: 'https://hooks.slack.com/services/xxx' })
  @IsString()
  @IsNotEmpty()
  url: string;

  @ApiPropertyOptional({
    description: 'Subscribed alert types',
    example: ['ATTACK_SPIKE', 'ML_DEGRADED', 'POLICY_SYNC_FAILED', 'FEEDBACK_EXPORT_READY'],
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  events?: string[];
}

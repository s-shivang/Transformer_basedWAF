import { IsEnum, IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { SiteStatus, OnboardingStatus } from '../../domain/protected-site.entity';

export class CreateProtectedSiteDto {
  @ApiProperty({ example: 'Main Production API' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ example: 'api.acme.com' })
  @IsString()
  @IsNotEmpty()
  domain: string;

  @ApiProperty({ example: 'https://backend.internal.acme.com' })
  @IsString()
  @IsNotEmpty()
  originUrl: string;
}

export class StartSiteOnboardingDto {
  @ApiProperty({ example: 'Checkout Gateway' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ example: 'checkout.acme.com' })
  @IsString()
  @IsNotEmpty()
  domain: string;

  @ApiProperty({ example: 'https://checkout-service.internal:8443' })
  @IsString()
  @IsNotEmpty()
  originUrl: string;
}

export class RetryOnboardingDto {
  @ApiPropertyOptional({ enum: OnboardingStatus, default: OnboardingStatus.PENDING_VERIFICATION })
  @IsOptional()
  @IsEnum(OnboardingStatus)
  targetStatus?: OnboardingStatus;
}

export class UpdateProtectedSiteDto {
  @ApiPropertyOptional({ example: 'Renamed API' })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({ example: 'https://new-origin.internal.acme.com' })
  @IsOptional()
  @IsString()
  originUrl?: string;

  @ApiPropertyOptional({ enum: SiteStatus, example: SiteStatus.ACTIVE })
  @IsOptional()
  @IsEnum(SiteStatus)
  status?: SiteStatus;
}

export class ConfigureSiteDto {
  @ApiPropertyOptional({ default: false })
  @IsOptional()
  forceRollback?: boolean;
}

export interface OnboardingInstructionsResponseDto {
  siteId: string;
  name: string;
  domain: string;
  originUrl: string;
  onboardingStatus: OnboardingStatus;
  verificationToken: string | null;
  configVersion: number;
  gatewayAckVersion: number | null;
  lastSyncedAt: string | null;
  txtRecord: {
    host: string;
    value: string | null;
    ttl: number;
  };
  trafficRecord: {
    type: 'CNAME';
    host: string;
    target: string;
  };
  lastError: string | null;
  verifiedAt: string | null;
}

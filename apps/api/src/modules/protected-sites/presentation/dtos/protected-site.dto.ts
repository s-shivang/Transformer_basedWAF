import { IsEnum, IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { SiteStatus } from '../../domain/protected-site.entity';

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

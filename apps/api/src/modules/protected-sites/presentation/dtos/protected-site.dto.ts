import { IsNotEmpty, IsString, IsUrl } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

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
  @IsUrl({ require_tld: false, protocols: ['http', 'https'] })
  @IsNotEmpty()
  originUrl: string;
}

export class UpdateProtectedSiteDto {
  @ApiProperty({ example: 'Renamed API', required: false })
  name?: string;

  @ApiProperty({ example: 'https://new-origin.internal.acme.com', required: false })
  originUrl?: string;

  @ApiProperty({ example: 'ACTIVE', enum: ['ACTIVE', 'PAUSED'], required: false })
  status?: string;
}


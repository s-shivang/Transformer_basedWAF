import { IsEnum, IsNotEmpty, IsOptional, IsString, Length, Matches } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { TenantTier } from '../../domain/tenant.entity';

export class CreateTenantRequestDto {
  @ApiProperty({ example: 'Acme Corp', description: 'Display name of the tenant' })
  @IsString()
  @IsNotEmpty()
  @Length(1, 100)
  name: string;

  @ApiProperty({
    example: 'acme-corp',
    description: 'Unique URL slug (3-50 chars, lowercase alphanumeric and hyphens)',
  })
  @IsString()
  @IsNotEmpty()
  @Length(3, 50)
  @Matches(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, {
    message: 'Slug must contain only lowercase alphanumeric characters and hyphens, and cannot start or end with a hyphen',
  })
  slug: string;

  @ApiPropertyOptional({ enum: TenantTier, default: TenantTier.FREE })
  @IsOptional()
  @IsEnum(TenantTier)
  tier?: TenantTier;
}

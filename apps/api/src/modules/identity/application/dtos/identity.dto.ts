import { UserRole } from '../../domain/user-role';

export interface UserResponseDto {
  id: string;
  email: string;
  name: string | null;
  isActive: boolean;
  createdAt: string;
}

export interface AuthSessionResponseDto {
  user: UserResponseDto;
  activeTenantId: string;
  role: UserRole;
  accessToken: string;
  refreshToken: string;
}

export interface MeResponseDto {
  user: UserResponseDto;
  activeTenantId: string;
  role: UserRole;
  memberships: {
    id: string;
    tenantId: string;
    role: UserRole;
  }[];
}

export interface MemberResponseDto {
  id: string;
  tenantId: string;
  userId: string;
  role: UserRole;
  createdAt: string;
}

export enum UserRole {
  OWNER = 'OWNER',
  ADMIN = 'ADMIN',
  ANALYST = 'ANALYST',
  VIEWER = 'VIEWER',
}

const ROLE_HIERARCHY: Record<UserRole, number> = {
  [UserRole.OWNER]: 4,
  [UserRole.ADMIN]: 3,
  [UserRole.ANALYST]: 2,
  [UserRole.VIEWER]: 1,
};

/**
 * Checks if the user's role satisfies any of the required roles or higher privilege.
 */
export function hasRequiredRole(userRole: UserRole, allowedRoles: UserRole[]): boolean {
  if (!userRole || !allowedRoles || allowedRoles.length === 0) {
    return false;
  }

  // Exact match
  if (allowedRoles.includes(userRole)) {
    return true;
  }

  // Hierarchical match: if an allowed role is VIEWER, ANALYST/ADMIN/OWNER also have access
  const minRequiredLevel = Math.min(...allowedRoles.map((r) => ROLE_HIERARCHY[r] ?? 999));
  const userLevel = ROLE_HIERARCHY[userRole] ?? 0;

  return userLevel >= minRequiredLevel;
}

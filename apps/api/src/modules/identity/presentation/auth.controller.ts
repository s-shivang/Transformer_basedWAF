import {
  Controller,
  Post,
  Get,
  Body,
  Req,
  Res,
  HttpStatus,
  HttpCode,
  HttpException,
  UseGuards,
  UnauthorizedException,
  Param,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { RegisterUseCase } from '../application/register.use-case';
import { LoginUseCase } from '../application/login.use-case';
import { RefreshTokenUseCase } from '../application/refresh-token.use-case';
import { LogoutUseCase } from '../application/logout.use-case';
import { AddMemberUseCase, ListMembersUseCase } from '../application/member-management.use-case';
import {
  RegisterRequestDto,
  LoginRequestDto,
  AddMemberRequestDto,
} from './dtos/auth.request.dtos';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { TenantScopeGuard } from './guards/tenant-scope.guard';
import { RolesGuard } from './guards/roles.guard';
import { Roles } from './guards/roles.decorator';
import { UserRole } from '../domain/user-role';
import { IUserRepository, IMembershipRepository, USER_REPOSITORY, MEMBERSHIP_REPOSITORY } from '../domain/identity.repository.interfaces';
import { Inject } from '@nestjs/common';

@ApiTags('Auth & Identity')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly registerUseCase: RegisterUseCase,
    private readonly loginUseCase: LoginUseCase,
    private readonly refreshTokenUseCase: RefreshTokenUseCase,
    private readonly logoutUseCase: LogoutUseCase,
    @Inject(USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(MEMBERSHIP_REPOSITORY) private readonly memberRepo: IMembershipRepository,
  ) {}

  @Post('register')
  @ApiOperation({ summary: 'Register a new tenant owner account' })
  @ApiResponse({ status: 201, description: 'User and tenant registered successfully' })
  @ApiResponse({ status: 409, description: 'Email or slug conflict' })
  async register(
    @Body() dto: RegisterRequestDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const clientIp = req.ip || req.socket.remoteAddress;
    const result = await this.registerUseCase.execute(dto, clientIp);

    if (result.isFailure) {
      const err = result.getError();
      const status = err.includes('already exists') ? HttpStatus.CONFLICT : HttpStatus.BAD_REQUEST;
      throw new HttpException(err, status);
    }

    const session = result.getValue();

    // Set HttpOnly Cookies
    this.setAuthCookies(res, session.accessToken, session.refreshToken);

    return {
      user: session.user,
      activeTenantId: session.activeTenantId,
      role: session.role,
      accessToken: session.accessToken,
    };
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login with email and password' })
  @ApiResponse({ status: 200, description: 'Authentication successful' })
  @ApiResponse({ status: 401, description: 'Invalid email or password' })
  async login(
    @Body() dto: LoginRequestDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const clientIp = req.ip || req.socket.remoteAddress;
    const result = await this.loginUseCase.execute(dto, clientIp);

    if (result.isFailure) {
      throw new UnauthorizedException(result.getError());
    }

    const session = result.getValue();
    this.setAuthCookies(res, session.accessToken, session.refreshToken);

    return {
      user: session.user,
      activeTenantId: session.activeTenantId,
      role: session.role,
      accessToken: session.accessToken,
    };
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Rotate refresh token and get new access token' })
  @ApiResponse({ status: 200, description: 'Tokens successfully refreshed' })
  @ApiResponse({ status: 401, description: 'Invalid or revoked refresh token' })
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies?.['waf_refresh_token'] || req.body?.refreshToken;
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token missing');
    }

    const result = await this.refreshTokenUseCase.execute(refreshToken);
    if (result.isFailure) {
      // Clear cookies on invalid refresh
      this.clearAuthCookies(res);
      throw new UnauthorizedException(result.getError());
    }

    const session = result.getValue();
    this.setAuthCookies(res, session.accessToken, session.refreshToken);

    return {
      accessToken: session.accessToken,
    };
  }

  @Post('logout')
  @ApiOperation({ summary: 'Logout and revoke refresh session' })
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies?.['waf_refresh_token'] || req.body?.refreshToken;
    const tenantCtx = req.tenantContext;
    const clientIp = req.ip || req.socket.remoteAddress;

    await this.logoutUseCase.execute(
      refreshToken,
      tenantCtx?.userId,
      tenantCtx?.tenantId,
      clientIp,
    );
    this.clearAuthCookies(res);

    return { message: 'Logged out successfully' };
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Get current authenticated user and tenant memberships' })
  async me(@Req() req: Request) {
    const ctx = req.tenantContext!;
    const user = await this.userRepo.findById(ctx.userId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const memberships = await this.memberRepo.findByUser(user.id);

    return {
      user: {
        id: user.id,
        email: user.email.value,
        name: user.name,
        isActive: user.isActive,
        createdAt: user.createdAt.toISOString(),
      },
      activeTenantId: ctx.tenantId,
      role: ctx.role,
      memberships: memberships.map((m) => ({
        id: m.id,
        tenantId: m.tenantId,
        role: m.role,
      })),
    };
  }

  private setAuthCookies(res: Response, accessToken: string, refreshToken: string) {
    res.cookie('waf_access_token', accessToken, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 15 * 60 * 1000, // 15 mins
    });

    res.cookie('waf_refresh_token', refreshToken, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
  }

  private clearAuthCookies(res: Response) {
    res.clearCookie('waf_access_token', { path: '/' });
    res.clearCookie('waf_refresh_token', { path: '/' });
  }
}

@ApiTags('Tenant Members')
@Controller('tenants/:tenantId/members')
@UseGuards(JwtAuthGuard, TenantScopeGuard, RolesGuard)
export class TenantMembersController {
  constructor(
    private readonly addMemberUseCase: AddMemberUseCase,
    private readonly listMembersUseCase: ListMembersUseCase,
  ) {}

  @Post()
  @Roles(UserRole.OWNER, UserRole.ADMIN)
  @ApiOperation({ summary: 'Add a new member to tenant (OWNER or ADMIN)' })
  async addMember(
    @Param('tenantId') tenantId: string,
    @Body() dto: AddMemberRequestDto,
    @Req() req: Request,
  ) {
    const ctx = req.tenantContext!;
    const clientIp = req.ip || req.socket.remoteAddress;

    const result = await this.addMemberUseCase.execute(
      tenantId,
      dto,
      ctx.role as UserRole,
      ctx.userId,
      clientIp,
    );

    if (result.isFailure) {
      throw new HttpException(result.getError(), HttpStatus.BAD_REQUEST);
    }

    return result.getValue();
  }

  @Get()
  @Roles(UserRole.OWNER, UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
  @ApiOperation({ summary: 'List all members of tenant' })
  async listMembers(@Param('tenantId') tenantId: string) {
    const result = await this.listMembersUseCase.execute(tenantId);
    return result.getValue();
  }
}

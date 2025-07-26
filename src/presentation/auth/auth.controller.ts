import { Controller, UseGuards, UsePipes, Logger } from '@nestjs/common';
import { Payload } from '@nestjs/microservices';
import { GrpcMethod } from '@nestjs/microservices';
import { Throttle, SkipThrottle } from '@nestjs/throttler';
import { AuthService } from '../../business-logic/services/auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import { Public } from './decorators/public.decorator';
import { Roles } from './decorators/roles.decorator';
import { User, UserRole } from '../../infrastructure/database/entities/user.entity';
import { GrpcValidationPipe } from './pipes/grpc-validation.pipe';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { ChangePasswordDto } from './dto/change-password.dto';

// gRPC Request interfaces for non-validated endpoints
interface ValidateTokenRequest {
  token: string;
}

interface RefreshTokenRequest {
  refreshToken: string;
}

interface LogoutRequest {
  token?: string;
  refreshToken?: string;
}

interface GetProfileRequest {
  userId: string;
}

interface UpdateProfileRequest {
  userId: string;
  firstName?: string;
  lastName?: string;
  email?: string;
}

interface ChangePasswordRequest {
  userId: string;
  currentPassword: string;
  newPassword: string;
}

// gRPC Response interfaces
interface AuthResponse {
  success: boolean;
  message: string;
  userData?: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    role: string;
    createdAt: number;
    updatedAt: number;
    isActive: boolean;
  };
  tokenData?: {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
    tokenType: string;
  };
  errors: string[];
}

interface ValidateTokenResponse {
  valid: boolean;
  userId?: string;
  email?: string;
  role?: string;
  exp?: number;
  message?: string;
}

interface UserProfileResponse {
  success: boolean;
  message: string;
  userData?: any;
  errors: string[];
}

interface LogoutResponse {
  success: boolean;
  message: string;
}

interface OperationResponse {
  success: boolean;
  message: string;
  errors: string[];
}

@Controller()
@UseGuards(JwtAuthGuard, RolesGuard)
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  private readonly logger = new Logger(AuthController.name);

  @Public()
  @Throttle({ registration: { limit: 1, ttl: 60000 } }) // 1 req/min (strict anti-spam)
  @GrpcMethod('AuthService', 'Register')
  @UsePipes(new GrpcValidationPipe())
  async register(request: RegisterDto): Promise<AuthResponse> {
    const result = await this.authService.register({
      email: request.email,
      password: request.password,
      firstName: request.firstName,
      lastName: request.lastName,
      role: request.role as UserRole || UserRole.USER,
    });

    return {
      success: result.success,
      message: result.message,
      userData: result.user ? {
        id: result.user.id!,
        email: result.user.email!,
        firstName: result.user.firstName!,
        lastName: result.user.lastName!,
        role: result.user.role! as string,
        createdAt: new Date(result.user.createdAt!).getTime(),
        updatedAt: new Date(result.user.updatedAt!).getTime(),
        isActive: result.user.isActive!,
      } : undefined,
      tokenData: result.tokens ? {
        accessToken: result.tokens.accessToken,
        refreshToken: result.tokens.refreshToken,
        expiresIn: result.tokens.expiresIn,
        tokenType: result.tokens.tokenType,
      } : undefined,
      errors: result.errors || [],
    };
  }

  @Public()
  @Throttle({ login: { limit: 5, ttl: 60000 } }) // 5 req/min (brute force protection)
  @GrpcMethod('AuthService', 'Login')
  @UsePipes(new GrpcValidationPipe())
  async login(request: LoginDto): Promise<AuthResponse> {
    const result = await this.authService.login({
      email: request.email,
      password: request.password,
    });

    return {
      success: result.success,
      message: result.message,
      userData: result.user ? {
        id: result.user.id!,
        email: result.user.email!,
        firstName: result.user.firstName!,
        lastName: result.user.lastName!,
        role: result.user.role! as string,
        createdAt: new Date(result.user.createdAt!).getTime(),
        updatedAt: new Date(result.user.updatedAt!).getTime(),
        isActive: result.user.isActive!,
      } : undefined,
      tokenData: result.tokens ? {
        accessToken: result.tokens.accessToken,
        refreshToken: result.tokens.refreshToken,
        expiresIn: result.tokens.expiresIn,
        tokenType: result.tokens.tokenType,
      } : undefined,
      errors: result.errors || [],
    };
  }

  @Public()
  @Throttle({ 'validate-token': { limit: 1000, ttl: 60000 } }) // High limit, essentially unlimited
  @GrpcMethod('AuthService', 'ValidateToken')
  async validateToken(request: ValidateTokenRequest): Promise<ValidateTokenResponse> {
    const result = await this.authService.validateToken(request.token);

    return {
      valid: result.valid,
      userId: result.user?.userId,
      email: result.user?.email,
      role: result.user?.role,
      exp: result.user?.exp,
      message: result.message,
    };
  }

  @Public()
  @Throttle({ refresh: { limit: 10, ttl: 60000 } }) // 10 req/min
  @GrpcMethod('AuthService', 'RefreshToken')
  async refreshToken(request: RefreshTokenRequest): Promise<AuthResponse> {
    const result = await this.authService.refreshTokens(request.refreshToken);

    return {
      success: result.success,
      message: result.message,
      tokenData: result.tokens ? {
        accessToken: result.tokens.accessToken,
        refreshToken: result.tokens.refreshToken,
        expiresIn: result.tokens.expiresIn,
        tokenType: result.tokens.tokenType,
      } : undefined,
      errors: result.errors || [],
    };
  }

  @Throttle({ logout: { limit: 10, ttl: 60000 } }) // 10 req/min
  @GrpcMethod('AuthService', 'Logout')
  async logout(request: LogoutRequest): Promise<LogoutResponse> {
    const result = await this.authService.logout(
      request.token,
      request.refreshToken,
      'User logout'
    );

    return {
      success: result.success,
      message: result.message,
    };
  }

  @Throttle({ profile: { limit: 30, ttl: 60000 } }) // 30 req/min
  @GrpcMethod('AuthService', 'GetProfile')
  async getProfile(
    @Payload() request: GetProfileRequest,
    @CurrentUser() currentUser: User
  ): Promise<UserProfileResponse> {
    // Debug log incoming request and current user
    try {
      this.logger.debug(`GetProfile request: ${JSON.stringify(request)}`);
      this.logger.debug(`Current user: ${JSON.stringify(currentUser?.id)}`);
    } catch (e) {}
    // Ensure user can only access their own profile or admin can access any
    if (request.userId !== currentUser.id && currentUser.role !== UserRole.ADMIN) {
      return {
        success: false,
        message: 'Access denied: Can only access your own profile',
        errors: ['Insufficient permissions'],
      };
    }

    const result = await this.authService.getProfile(request.userId);

    return {
      success: result.success,
      message: result.message,
      userData: result.user ? {
        id: result.user.id!,
        email: result.user.email!,
        firstName: result.user.firstName!,
        lastName: result.user.lastName!,
        role: result.user.role! as string,
        createdAt: new Date(result.user.createdAt!).getTime(),
        updatedAt: new Date(result.user.updatedAt!).getTime(),
        isActive: result.user.isActive!,
      } : undefined,
      errors: result.errors || [],
    };
  }

  @Throttle({ 'update-profile': { limit: 10, ttl: 60000 } }) // 10 req/min
  @GrpcMethod('AuthService', 'UpdateProfile')
  async updateProfile(
    request: UpdateProfileRequest,
    @CurrentUser() currentUser: User
  ): Promise<UserProfileResponse> {
    // Ensure user can only update their own profile or admin can update any
    if (request.userId !== currentUser.id && currentUser.role !== UserRole.ADMIN) {
      return {
        success: false,
        message: 'Access denied: Can only update your own profile',
        errors: ['Insufficient permissions'],
      };
    }

    // Validate the update fields using the DTO
    const updateDto = new UpdateProfileDto();
    updateDto.firstName = request.firstName;
    updateDto.lastName = request.lastName;
    updateDto.email = request.email;
    
    const validationPipe = new GrpcValidationPipe();
    await validationPipe.transform(updateDto, { metatype: UpdateProfileDto, type: 'body' });

    const result = await this.authService.updateProfile(request.userId, {
      firstName: request.firstName,
      lastName: request.lastName,
      email: request.email,
    });

    return {
      success: result.success,
      message: result.message,
      userData: result.user ? {
        id: result.user.id!,
        email: result.user.email!,
        firstName: result.user.firstName!,
        lastName: result.user.lastName!,
        role: result.user.role! as string,
        createdAt: new Date(result.user.createdAt!).getTime(),
        updatedAt: new Date(result.user.updatedAt!).getTime(),
        isActive: result.user.isActive!,
      } : undefined,
      errors: result.errors || [],
    };
  }

  @Throttle({ 'password-change': { limit: 3, ttl: 60000 } }) // 3 req/min (strict security)
  @GrpcMethod('AuthService', 'ChangePassword')
  async changePassword(
    request: ChangePasswordRequest,
    @CurrentUser() currentUser: User
  ): Promise<OperationResponse> {
    // Ensure user can only change their own password or admin can change any
    if (request.userId !== currentUser.id && currentUser.role !== UserRole.ADMIN) {
      return {
        success: false,
        message: 'Access denied: Can only change your own password',
        errors: ['Insufficient permissions'],
      };
    }

    // Validate the password change request using the DTO
    const changePasswordDto = new ChangePasswordDto();
    changePasswordDto.currentPassword = request.currentPassword;
    changePasswordDto.newPassword = request.newPassword;
    
    const validationPipe = new GrpcValidationPipe();
    await validationPipe.transform(changePasswordDto, { metatype: ChangePasswordDto, type: 'body' });

    const result = await this.authService.changePassword(
      request.userId,
      request.currentPassword,
      request.newPassword
    );

    return {
      success: result.success,
      message: result.message,
      errors: result.errors || [],
    };
  }
} 
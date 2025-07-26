import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { UserRepository } from '../../infrastructure/database/repositories/user.repository';
import { RefreshTokenRepository } from '../../infrastructure/database/repositories/refresh-token.repository';
import { JwtTokenService, TokenPair, DecodedToken } from './jwt.service';
import { PasswordService } from './password.service';
import { User, UserRole } from '../../infrastructure/database/entities/user.entity';

export interface RegisterUserDto {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  role?: UserRole;
}

export interface LoginDto {
  email: string;
  password: string;
}

export interface AuthResult {
  success: boolean;
  message: string;
  user?: Partial<User>;
  tokens?: TokenPair;
  errors?: string[];
}

export interface ValidationResult {
  valid: boolean;
  user?: DecodedToken;
  message?: string;
}

export interface UserProfileDto {
  firstName?: string;
  lastName?: string;
  email?: string;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly refreshTokenRepository: RefreshTokenRepository,
    private readonly jwtTokenService: JwtTokenService,
    private readonly passwordService: PasswordService,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Register a new user
   */
  async register(
    registerData: RegisterUserDto,
    options?: { ipAddress?: string; userAgent?: string }
  ): Promise<AuthResult> {
    try {
      const { email, password, firstName, lastName, role = UserRole.USER } = registerData;

      // Normalize email
      const normalizedEmail = email.toLowerCase().trim();

      // Check if user already exists
      const existingUser = await this.userRepository.findByEmail(normalizedEmail);
      if (existingUser) {
        return {
          success: false,
          message: 'User with this email already exists',
          errors: ['Email is already registered'],
        };
      }

      // Validate password strength
      const passwordValidation = this.passwordService.validatePasswordStrength(password);
      if (!passwordValidation.isValid) {
        return {
          success: false,
          message: 'Password does not meet security requirements',
          errors: passwordValidation.errors,
        };
      }

      // Hash password
      const passwordHash = await this.passwordService.hashPassword(password);

      // Create user
      const user = await this.userRepository.create({
        email: normalizedEmail,
        passwordHash,
        firstName: firstName.trim(),
        lastName: lastName.trim(),
        role,
      });

      // Generate tokens
      const tokens = await this.jwtTokenService.generateTokenPair(user, options);

      return {
        success: true,
        message: 'User registered successfully',
        user: user.toSafeObject(),
        tokens,
      };
    } catch (error) {
      throw new BadRequestException(`Registration failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Login user with email and password
   */
  async login(
    loginData: LoginDto,
    options?: { ipAddress?: string; userAgent?: string }
  ): Promise<AuthResult> {
    const { email, password } = loginData;

    // Find user by email
    const user = await this.userRepository.findByEmail(email.toLowerCase().trim());
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if user account is active
    if (!user.isActive) {
      throw new UnauthorizedException('Account is deactivated');
    }

    // Verify password
    const isPasswordValid = await this.passwordService.verifyPassword(password, user.passwordHash);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if password needs rehashing
    const needsRehash = await this.passwordService.needsRehash(user.passwordHash);
    if (needsRehash) {
      const newHash = await this.passwordService.hashPassword(password);
      await this.userRepository.updatePassword(user.id, newHash);
    }

    // Update last login time
    await this.userRepository.updateLastLoginAt(user.id);

    // Generate tokens
    const tokens = await this.jwtTokenService.generateTokenPair(user, options);

    return {
      success: true,
      message: 'Login successful',
      user: user.toSafeObject(),
      tokens,
    };
  }

  /**
   * Validate access token
   */
  async validateToken(token: string): Promise<ValidationResult> {
    try {
      const decodedToken = await this.jwtTokenService.validateAccessToken(token);
      
      // Verify user still exists and is active
      const user = await this.userRepository.findById(decodedToken.userId);
      if (!user || !user.isActive) {
        return {
          valid: false,
          message: 'User account not found or inactive',
        };
      }

      return {
        valid: true,
        user: decodedToken,
      };
    } catch (error) {
      return {
        valid: false,
        message: error instanceof Error ? error.message : 'Invalid token',
      };
    }
  }

  /**
   * Refresh access tokens
   */
  async refreshTokens(
    refreshToken: string,
    options?: { ipAddress?: string; userAgent?: string }
  ): Promise<AuthResult> {
    try {
      const tokens = await this.jwtTokenService.refreshTokens(refreshToken, options);

      return {
        success: true,
        message: 'Tokens refreshed successfully',
        tokens,
      };
    } catch (error) {
      throw new UnauthorizedException(`Token refresh failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Logout user (revoke refresh token)
   */
  async logout(
    accessToken?: string,
    refreshToken?: string,
    reason: string = 'User logout'
  ): Promise<{ success: boolean; message: string }> {
    try {
      if (refreshToken) {
        await this.jwtTokenService.revokeRefreshToken(refreshToken, reason);
      }

      // Optional: You could also maintain a blacklist for access tokens
      // if you need immediate token invalidation

      return {
        success: true,
        message: 'Logout successful',
      };
    } catch (error) {
      return {
        success: false,
        message: `Logout failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  /**
   * Get user profile
   */
  async getProfile(userId: string): Promise<AuthResult> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    return {
      success: true,
      message: 'Profile retrieved successfully',
      user: user.toSafeObject(),
    };
  }

  /**
   * Update user profile
   */
  async updateProfile(
    userId: string,
    updateData: UserProfileDto
  ): Promise<AuthResult> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // If email is being updated, check for conflicts
    if (updateData.email && updateData.email !== user.email) {
      const existingUser = await this.userRepository.findByEmail(updateData.email.toLowerCase());
      if (existingUser) {
        return {
          success: false,
          message: 'Email is already in use',
          errors: ['Email is already registered to another account'],
        };
      }
    }

    // Update user
    const updatedUser = await this.userRepository.update(userId, {
      firstName: updateData.firstName?.trim(),
      lastName: updateData.lastName?.trim(),
      email: updateData.email?.toLowerCase().trim(),
    });

    return {
      success: true,
      message: 'Profile updated successfully',
      user: updatedUser?.toSafeObject(),
    };
  }

  /**
   * Change user password
   */
  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string
  ): Promise<{ success: boolean; message: string; errors?: string[] }> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Verify current password
    const isCurrentPasswordValid = await this.passwordService.verifyPassword(
      currentPassword,
      user.passwordHash
    );
    if (!isCurrentPasswordValid) {
      return {
        success: false,
        message: 'Current password is incorrect',
        errors: ['Current password is invalid'],
      };
    }

    // Validate new password strength
    const passwordValidation = this.passwordService.validatePasswordStrength(newPassword);
    if (!passwordValidation.isValid) {
      return {
        success: false,
        message: 'New password does not meet security requirements',
        errors: passwordValidation.errors,
      };
    }

    // Hash new password
    const newPasswordHash = await this.passwordService.hashPassword(newPassword);

    // Update password and revoke all refresh tokens for security
    await this.userRepository.updatePassword(userId, newPasswordHash);
    await this.jwtTokenService.revokeAllUserTokens(userId, 'Password changed');

    return {
      success: true,
      message: 'Password changed successfully. Please login again.',
    };
  }

  /**
   * Revoke all user sessions (logout from all devices)
   */
  async revokeAllSessions(
    userId: string,
    reason: string = 'All sessions revoked by user'
  ): Promise<{ success: boolean; message: string }> {
    await this.jwtTokenService.revokeAllUserTokens(userId, reason);

    return {
      success: true,
      message: 'All sessions revoked successfully',
    };
  }

  /**
   * Get user by ID for Passport strategy
   */
  async getUserById(userId: string): Promise<User | null> {
    return await this.userRepository.findById(userId);
  }

  /**
   * Get user by email for Passport strategy
   */
  async getUserByEmail(email: string): Promise<User | null> {
    return await this.userRepository.findByEmail(email);
  }

  /**
   * Verify user for Passport local strategy
   */
  async verifyUser(email: string, password: string): Promise<User | null> {
    const user = await this.userRepository.findByEmail(email.toLowerCase());
    if (!user || !user.isActive) {
      return null;
    }

    const isPasswordValid = await this.passwordService.verifyPassword(password, user.passwordHash);
    if (!isPasswordValid) {
      return null;
    }

    return user;
  }

  /**
   * Cleanup expired tokens (for scheduled tasks)
   */
  async cleanupExpiredTokens(): Promise<number> {
    return await this.jwtTokenService.cleanupExpiredTokens();
  }
} 
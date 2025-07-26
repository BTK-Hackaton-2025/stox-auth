import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService as NestJwtService } from '@nestjs/jwt';
import { User } from '../../infrastructure/database/entities/user.entity';
import { RefreshTokenRepository } from '../../infrastructure/database/repositories/refresh-token.repository';
import { v4 as uuidv4 } from 'uuid';

export interface JwtPayload {
  sub: string; // Subject (user ID)
  email: string;
  role: string;
  iat?: number; // Issued at
  exp?: number; // Expiration time
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
}

export interface DecodedToken {
  userId: string;
  email: string;
  role: string;
  exp: number;
  iat: number;
}

@Injectable()
export class JwtTokenService {
  private readonly accessTokenSecret: string;
  private readonly refreshTokenSecret: string;
  private readonly accessTokenExpiresIn: string;
  private readonly refreshTokenExpiresIn: string;

  constructor(
    private readonly jwtService: NestJwtService,
    private readonly configService: ConfigService,
    private readonly refreshTokenRepository: RefreshTokenRepository,
  ) {
    this.accessTokenSecret = this.configService.get<string>('JWT_ACCESS_SECRET') || 'access-secret';
    this.refreshTokenSecret = this.configService.get<string>('JWT_REFRESH_SECRET') || 'refresh-secret';
    this.accessTokenExpiresIn = this.configService.get<string>('JWT_ACCESS_EXPIRES_IN') || '15m';
    this.refreshTokenExpiresIn = this.configService.get<string>('JWT_REFRESH_EXPIRES_IN') || '7d';
  }

  /**
   * Generate access and refresh token pair
   */
  async generateTokenPair(
    user: User,
    options?: { ipAddress?: string; userAgent?: string }
  ): Promise<TokenPair> {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
    };

    // Generate access token
    const accessToken = this.jwtService.sign(payload, {
      secret: this.accessTokenSecret,
      expiresIn: this.accessTokenExpiresIn,
    });

    // Generate refresh token
    const refreshTokenId = uuidv4();
    const refreshToken = this.jwtService.sign(
      { sub: user.id, tokenId: refreshTokenId },
      {
        secret: this.refreshTokenSecret,
        expiresIn: this.refreshTokenExpiresIn,
      }
    );

    // Calculate expiration date for refresh token
    const expiresAt = new Date();
    const expiresInMs = this.parseExpirationTime(this.refreshTokenExpiresIn);
    expiresAt.setTime(expiresAt.getTime() + expiresInMs);

    // Store refresh token in database
    await this.refreshTokenRepository.create({
      token: refreshToken,
      userId: user.id,
      expiresAt,
      ipAddress: options?.ipAddress,
      userAgent: options?.userAgent,
    });

    // Get access token expiration in seconds
    const accessTokenExpiresInSeconds = this.parseExpirationTime(this.accessTokenExpiresIn) / 1000;

    return {
      accessToken,
      refreshToken,
      expiresIn: accessTokenExpiresInSeconds,
      tokenType: 'Bearer',
    };
  }

  /**
   * Validate and decode access token
   */
  async validateAccessToken(token: string): Promise<DecodedToken> {
    try {
      const decoded = this.jwtService.verify(token, {
        secret: this.accessTokenSecret,
      });

      return {
        userId: decoded.sub,
        email: decoded.email,
        role: decoded.role,
        exp: decoded.exp,
        iat: decoded.iat,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired access token');
    }
  }

  /**
   * Validate refresh token and generate new token pair
   */
  async refreshTokens(
    refreshToken: string,
    options?: { ipAddress?: string; userAgent?: string }
  ): Promise<TokenPair> {
    try {
      // Verify refresh token signature
      const decoded = this.jwtService.verify(refreshToken, {
        secret: this.refreshTokenSecret,
      });

      // Check if refresh token exists in database and is valid
      const storedToken = await this.refreshTokenRepository.findValidByToken(refreshToken);
      
      if (!storedToken || !storedToken.isValid()) {
        throw new UnauthorizedException('Invalid or expired refresh token');
      }

      const user = storedToken.user;
      if (!user || !user.isActive) {
        throw new UnauthorizedException('User account is inactive');
      }

      // Revoke old refresh token
      await this.refreshTokenRepository.revokeToken(refreshToken, 'Used for token refresh');

      // Generate new token pair
      return await this.generateTokenPair(user, options);
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  /**
   * Revoke refresh token
   */
  async revokeRefreshToken(refreshToken: string, reason?: string): Promise<void> {
    await this.refreshTokenRepository.revokeToken(refreshToken, reason);
  }

  /**
   * Revoke all user refresh tokens
   */
  async revokeAllUserTokens(userId: string, reason?: string): Promise<void> {
    await this.refreshTokenRepository.revokeAllUserTokens(userId, reason);
  }

  /**
   * Decode token without verification (for expired token inspection)
   */
  decodeToken(token: string): any {
    return this.jwtService.decode(token);
  }

  /**
   * Check if token is expired
   */
  isTokenExpired(token: string): boolean {
    try {
      const decoded = this.decodeToken(token);
      if (!decoded || !decoded.exp) {
        return true;
      }
      
      const currentTime = Math.floor(Date.now() / 1000);
      return decoded.exp < currentTime;
    } catch {
      return true;
    }
  }

  /**
   * Get token expiration date
   */
  getTokenExpiration(token: string): Date | null {
    try {
      const decoded = this.decodeToken(token);
      if (!decoded || !decoded.exp) {
        return null;
      }
      return new Date(decoded.exp * 1000);
    } catch {
      return null;
    }
  }

  /**
   * Parse expiration time string to milliseconds
   */
  private parseExpirationTime(expiresIn: string): number {
    const unit = expiresIn.slice(-1);
    const value = parseInt(expiresIn.slice(0, -1));

    switch (unit) {
      case 's':
        return value * 1000;
      case 'm':
        return value * 60 * 1000;
      case 'h':
        return value * 60 * 60 * 1000;
      case 'd':
        return value * 24 * 60 * 60 * 1000;
      default:
        return 15 * 60 * 1000; // Default to 15 minutes
    }
  }

  /**
   * Clean up expired tokens (should be called periodically)
   */
  async cleanupExpiredTokens(): Promise<number> {
    return await this.refreshTokenRepository.cleanupExpiredTokens();
  }
} 
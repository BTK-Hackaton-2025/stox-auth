import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthService } from '../../../business-logic/services/auth.service';
import { User } from '../../../infrastructure/database/entities/user.entity';

export interface JwtPayload {
  sub: string; // User ID
  email: string;
  role: string;
  iat: number;
  exp: number;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_ACCESS_SECRET') || 'access-secret',
      algorithms: ['HS256'],
    });
  }

  /**
   * Passport will call this method after successfully verifying the JWT signature
   * The payload is the decoded JWT
   */
  async validate(payload: JwtPayload): Promise<User> {
    const { sub: userId, email, role } = payload;

    // Get user from database to ensure they still exist and are active
    const user = await this.authService.getUserById(userId);
    
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('User account is deactivated');
    }

    // Verify that the token data matches current user data
    if (user.email !== email || user.role !== role) {
      throw new UnauthorizedException('Token data mismatch');
    }

    // Return user object (will be attached to req.user)
    return user;
  }

  /**
   * Handle authentication failure
   */
  handleRequest(err: any, user: any, info: any) {
    if (err) {
      throw err;
    }
    
    if (!user) {
      let message = 'Unauthorized';
      
      if (info?.name === 'TokenExpiredError') {
        message = 'Access token has expired';
      } else if (info?.name === 'JsonWebTokenError') {
        message = 'Invalid access token';
      } else if (info?.name === 'NotBeforeError') {
        message = 'Access token not active yet';
      } else if (info?.message) {
        message = info.message;
      }
      
      throw new UnauthorizedException(message);
    }
    
    return user;
  }
} 
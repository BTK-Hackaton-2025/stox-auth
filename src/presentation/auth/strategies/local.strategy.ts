import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../../../business-logic/services/auth.service';
import { User } from '../../../infrastructure/database/entities/user.entity';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly authService: AuthService) {
    super({
      usernameField: 'email', // Use email instead of username
      passwordField: 'password',
      passReqToCallback: false,
    });
  }

  /**
   * Passport will call this method to verify the user credentials
   * This is used primarily for the login process
   */
  async validate(email: string, password: string): Promise<User> {
    // Validate input
    if (!email || !password) {
      throw new UnauthorizedException('Email and password are required');
    }

    // Verify user credentials using the auth service
    const user = await this.authService.verifyUser(email, password);
    
    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
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
      throw new UnauthorizedException('Invalid email or password');
    }
    
    return user;
  }
} 
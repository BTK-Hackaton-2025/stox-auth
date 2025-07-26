import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { Observable } from 'rxjs';
import { JwtTokenService } from '../../../business-logic/services/jwt.service';
import { AuthService } from '../../../business-logic/services/auth.service';
import { Metadata } from '@grpc/grpc-js';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(
    private reflector: Reflector,
    private jwtTokenService: JwtTokenService,
    private authService: AuthService,
  ) {
    super();
    this.logger = new Logger(JwtAuthGuard.name);
  }

  private readonly logger: Logger;

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    // Check if route is marked as public
    const isPublic = this.reflector.getAllAndOverride<boolean>('isPublic', [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    // For gRPC context, we need to handle the metadata differently
    const contextType = context.getType();
    
    if (contextType === 'rpc') {
      return this.handleGrpcContext(context);
    }

    // Default HTTP context handling
    return super.canActivate(context);
  }

  /**
   * Handle gRPC context authentication
   */
  private async handleGrpcContext(context: ExecutionContext): Promise<boolean> {
    try {
      const data = context.switchToRpc().getData();
      const metadata = context.switchToRpc().getContext();

      // Debug logs for incoming payload and metadata
      try {
        this.logger.debug(`gRPC payload: ${JSON.stringify(data)}`);

        let metadataObj: any;
        if (metadata && typeof (metadata as Metadata).getMap === 'function') {
          metadataObj = (metadata as Metadata).getMap();
        } else {
          metadataObj = metadata;
        }
        this.logger.debug(`gRPC metadata: ${JSON.stringify(metadataObj)}`);
      } catch (logErr) {
        // swallow logging errors
      }

      // Support both plain-object metadata (e.g. Gateway) and @grpc/grpc-js Metadata instance
      let authorization: any;

      if (metadata && typeof (metadata as Metadata).get === 'function') {
        // gRPC Metadata instance
        const md = metadata as Metadata;
        authorization = (md.get('authorization')[0] || md.get('Authorization')[0]) as string | undefined;
        if (Array.isArray(authorization)) {
          authorization = authorization[0];
        }
      } else {
        // Plain object case
        authorization = (metadata as any)?.authorization || (metadata as any)?.Authorization;
      }

      // Extract token from gRPC metadata
      const token = authorization.replace('Bearer ', '');
      if (!token) {
        throw new UnauthorizedException('Invalid authorization format');
      }

      // Validate the access token
      const decodedToken = await this.jwtTokenService.validateAccessToken(token);
      
      // Get the user from database to ensure they still exist and are active
      const user = await this.authService.getUserById(decodedToken.userId);
      
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      if (!user.isActive) {
        throw new UnauthorizedException('User account is deactivated');
      }

      // Verify that the token data matches current user data
      if (user.email !== decodedToken.email || user.role !== decodedToken.role) {
        throw new UnauthorizedException('Token data mismatch');
      }

      // Attach user to gRPC context for use by other guards and decorators
      metadata.user = user;

      return true;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('Authentication failed');
    }
  }

  /**
   * Handle authentication errors
   */
  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    if (err || !user) {
      const contextType = context.getType();
      
      let message = 'Unauthorized access';
      
      if (info?.name === 'TokenExpiredError') {
        message = 'Access token has expired';
      } else if (info?.name === 'JsonWebTokenError') {
        message = 'Invalid access token';
      } else if (info?.message) {
        message = info.message;
      } else if (err?.message) {
        message = err.message;
      }

      throw new UnauthorizedException(message);
    }

    return user;
  }
} 
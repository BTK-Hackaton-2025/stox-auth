import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UserRole } from '../../../infrastructure/database/entities/user.entity';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    // Get required roles from decorator metadata
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>('roles', [
      context.getHandler(),
      context.getClass(),
    ]);

    // If no roles are required, allow access
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    // Get user from request context
    const contextType = context.getType();
    let user: any;

    if (contextType === 'rpc') {
      // For gRPC context
      const grpcContext = context.switchToRpc().getContext();
      user = grpcContext.user;
    } else {
      // For HTTP context
      const request = context.switchToHttp().getRequest();
      user = request.user;
    }

    // Check if user exists (should be set by authentication guard)
    if (!user) {
      throw new ForbiddenException('User not authenticated');
    }

    // Check if user has required role
    const hasRequiredRole = requiredRoles.some(role => user.role === role);

    if (!hasRequiredRole) {
      throw new ForbiddenException(
        `Access denied. Required roles: ${requiredRoles.join(', ')}. User role: ${user.role}`
      );
    }

    return true;
  }
} 
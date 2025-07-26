import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { User } from '../../../infrastructure/database/entities/user.entity';

/**
 * Decorator to extract the current authenticated user from request context
 * Works with both HTTP and gRPC contexts
 * 
 * Usage:
 * async getProfile(@CurrentUser() user: User) { ... }
 * async getProfile(@CurrentUser('id') userId: string) { ... }
 */
export const CurrentUser = createParamDecorator(
  (property: keyof User | undefined, context: ExecutionContext) => {
    const contextType = context.getType();
    let user: User;

    if (contextType === 'rpc') {
      // For gRPC context
      const grpcContext = context.switchToRpc().getContext();
      user = grpcContext.user;
    } else {
      // For HTTP context
      const request = context.switchToHttp().getRequest();
      user = request.user;
    }

    if (!user) {
      return null;
    }

    // Return specific property if requested, otherwise return full user
    return property ? user[property] : user;
  },
); 
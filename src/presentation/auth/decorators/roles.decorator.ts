import { SetMetadata } from '@nestjs/common';
import { UserRole } from '../../../infrastructure/database/entities/user.entity';

/**
 * Decorator to specify required roles for accessing a route or controller
 * 
 * Usage:
 * @Roles(UserRole.ADMIN)
 * @Roles(UserRole.ADMIN, UserRole.MODERATOR)
 */
export const Roles = (...roles: UserRole[]) => SetMetadata('roles', roles); 
import { SetMetadata } from '@nestjs/common';

/**
 * Decorator to mark routes as public (no authentication required)
 * 
 * Usage:
 * @Public()
 * async register() { ... }
 */
export const Public = () => SetMetadata('isPublic', true); 
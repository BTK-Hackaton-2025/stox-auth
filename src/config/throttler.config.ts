import { ThrottlerModuleOptions } from '@nestjs/throttler';

// Rate limiting configuration based on README specifications
export const throttlerConfig: ThrottlerModuleOptions = [
  {
    name: 'default',
    ttl: 60000, // 1 minute window
    limit: 100, // Default 100 requests per minute
  },
  {
    name: 'strict',
    ttl: 60000, // 1 minute window  
    limit: 10, // For sensitive operations
  },
  {
    name: 'very-strict',
    ttl: 60000, // 1 minute window
    limit: 3, // For password changes
  },
  {
    name: 'registration',
    ttl: 60000, // 1 minute window
    limit: 1, // Registration: 1 req/min (strict anti-spam)
  },
];

// Custom rate limiting configurations for specific auth operations
export const AuthRateLimits = {
  // Registration: 1 req/min (strict anti-spam)
  REGISTER: {
    name: 'registration',
    ttl: 60000,
    limit: 1,
  },
  
  // Login: 5 req/min (brute force protection)
  LOGIN: {
    name: 'login',
    ttl: 60000,
    limit: 5,
  },
  
  // Token validation: Unlimited (performance optimization)
  VALIDATE_TOKEN: {
    name: 'validate-token',
    ttl: 60000,
    limit: 1000, // High limit, essentially unlimited
  },
  
  // Token refresh: 10 req/min
  REFRESH_TOKEN: {
    name: 'refresh',
    ttl: 60000,
    limit: 10,
  },
  
  // Logout: 10 req/min
  LOGOUT: {
    name: 'logout',
    ttl: 60000,
    limit: 10,
  },
  
  // Get profile: 30 req/min
  GET_PROFILE: {
    name: 'profile',
    ttl: 60000,
    limit: 30,
  },
  
  // Update profile: 10 req/min
  UPDATE_PROFILE: {
    name: 'update-profile',
    ttl: 60000,
    limit: 10,
  },
  
  // Password changes: 3 req/min (strict security)
  CHANGE_PASSWORD: {
    name: 'password-change',
    ttl: 60000,
    limit: 3,
  },
} as const;

// Extended throttler config with all auth-specific limits
export const extendedThrottlerConfig: ThrottlerModuleOptions = [
  ...throttlerConfig,
  AuthRateLimits.LOGIN,
  AuthRateLimits.VALIDATE_TOKEN,
  AuthRateLimits.REFRESH_TOKEN,
  AuthRateLimits.LOGOUT,
  AuthRateLimits.GET_PROFILE,
  AuthRateLimits.UPDATE_PROFILE,
  AuthRateLimits.CHANGE_PASSWORD,
]; 
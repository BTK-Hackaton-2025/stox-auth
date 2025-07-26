import pino from 'pino';
import { ConfigService } from '@nestjs/config';
import { LoggerService } from '@nestjs/common';

export interface LoggerConfig {
  level: string;
  name: string;
  redact: {
    paths: string[];
    remove: boolean;
  };
  serializers: Record<string, (value: any) => any>;
  formatters?: {
    level: (label: string, number: number) => object;
  };
  transport?: pino.TransportSingleOptions;
}

export const createLoggerConfig = (serviceName: string = 'stox-auth-service'): LoggerConfig => {
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  const config: LoggerConfig = {
    name: serviceName,
    level: process.env.LOG_LEVEL || (isDevelopment ? 'debug' : 'info'),
    redact: {
      paths: [
        // Sensitive authentication data
        'password',
        'token',
        'refreshToken',
        'accessToken',
        'authorization',
        'passwordHash',
        'currentPassword',
        'newPassword',
        
        // Request/response sensitive fields
        'req.headers.authorization',
        'req.body.password',
        'req.body.currentPassword',
        'req.body.newPassword',
        'res.tokens',
        'res.accessToken',
        'res.refreshToken',
        
        // Nested sensitive fields
        '*.password',
        '*.token',
        '*.passwordHash',
        '*.authorization',
        'tokens.accessToken',
        'tokens.refreshToken',
      ],
      remove: true, // Completely remove sensitive fields
    },
    serializers: {
      // Standard pino serializers for HTTP requests/responses
      ...pino.stdSerializers,
      
      // Custom user serializer - only log safe user data
      user: (user: any) => {
        if (!user) return user;
        return {
          id: user.id,
          email: user.email,
          role: user.role,
          isActive: user.isActive,
          firstName: user.firstName,
          lastName: user.lastName,
          createdAt: user.createdAt,
        };
      },
      
      // Custom error serializer with more context
      err: (error: any) => {
        if (!error) return error;
        return {
          type: error.constructor?.name,
          message: error.message,
          stack: error.stack,
          code: error.code,
          status: error.status,
          // Don't log sensitive error details in production
          ...(process.env.NODE_ENV === 'development' && { details: error }),
        };
      },
      
      // Auth event serializer
      authEvent: (event: any) => {
        if (!event) return event;
        return {
          type: event.type,
          userId: event.userId,
          success: event.success,
          ipAddress: event.ipAddress,
          userAgent: event.userAgent,
          timestamp: event.timestamp || new Date().toISOString(),
        };
      },
    },
    formatters: {
      level: (label: string, number: number) => {
        return { level: number, severity: label.toUpperCase() };
      },
    },
  };

  // Add pretty printing for development
  if (isDevelopment) {
    config.transport = {
      target: 'pino-pretty',
      options: {
        colorize: true,
        translateTime: 'SYS:standard',
        ignore: 'hostname,pid',
        singleLine: false,
        hideObject: false,
      },
    };
  }

  return config;
};

export const createLogger = (serviceName?: string) => {
  const config = createLoggerConfig(serviceName);
  return pino(config);
};

// Create application-wide logger instance
export const logger = createLogger();

// NestJS Logger Service Adapter
export class PinoLoggerService implements LoggerService {
  constructor(private readonly pinoLogger = logger) {}

  log(message: any, ...optionalParams: any[]) {
    this.pinoLogger.info(message, ...optionalParams);
  }

  error(message: any, ...optionalParams: any[]) {
    this.pinoLogger.error(message, ...optionalParams);
  }

  warn(message: any, ...optionalParams: any[]) {
    this.pinoLogger.warn(message, ...optionalParams);
  }

  debug(message: any, ...optionalParams: any[]) {
    this.pinoLogger.debug(message, ...optionalParams);
  }

  verbose(message: any, ...optionalParams: any[]) {
    this.pinoLogger.trace(message, ...optionalParams);
  }
}

// Helper functions for common auth logging patterns
export const logAuthEvent = (
  eventType: 'login' | 'register' | 'logout' | 'token_refresh' | 'password_change',
  data: {
    userId?: string;
    email?: string;
    success: boolean;
    ipAddress?: string;
    userAgent?: string;
    error?: string;
  }
) => {
  const logData = {
    event: 'auth',
    type: eventType,
    ...data,
    timestamp: new Date().toISOString(),
  };

  if (data.success) {
    logger.info(logData, `Auth ${eventType} successful`);
  } else {
    logger.warn(logData, `Auth ${eventType} failed`);
  }
};

export const logSecurityEvent = (
  eventType: 'suspicious_login' | 'rate_limit_exceeded' | 'invalid_token' | 'account_locked',
  data: {
    userId?: string;
    email?: string;
    ipAddress?: string;
    userAgent?: string;
    details?: string;
  }
) => {
  logger.warn(
    {
      event: 'security',
      type: eventType,
      ...data,
      timestamp: new Date().toISOString(),
    },
    `Security event: ${eventType}`
  );
}; 
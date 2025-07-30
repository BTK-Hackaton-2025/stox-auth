import { Module, MiddlewareConsumer, RequestMethod } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import pinoHttp from 'pino-http';
import { v4 as uuidv4 } from 'uuid';

// Entities
import { User } from '../../infrastructure/database/entities/user.entity';
import { RefreshToken } from '../../infrastructure/database/entities/refresh-token.entity';

// Repositories
import { UserRepository } from '../../infrastructure/database/repositories/user.repository';
import { RefreshTokenRepository } from '../../infrastructure/database/repositories/refresh-token.repository';

// Services
import { AuthService } from '../../business-logic/services/auth.service';
import { JwtTokenService } from '../../business-logic/services/jwt.service';
import { PasswordService } from '../../business-logic/services/password.service';

// Controllers
import { AuthController } from './auth.controller';

// Strategies
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';

// Guards
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { GrpcExceptionFilter } from './filters/grpc-exception.filter';
import { GrpcValidationPipe } from './pipes/grpc-validation.pipe';
import { logger } from '../../config/logger.config';

@Module({
  imports: [
    // Configuration module
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env.local', '.env'],
    }),

    // TypeORM for database entities
    TypeOrmModule.forFeature([User, RefreshToken]),

    // Passport for authentication strategies
    PassportModule.register({
      defaultStrategy: 'jwt',
      property: 'user',
      session: false,
    }),

    // JWT module configuration
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_ACCESS_SECRET') || 'access-secret',
        signOptions: {
          expiresIn: configService.get<string>('JWT_ACCESS_EXPIRES_IN') || '15m',
          algorithm: 'HS256',
        },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [
    // Repositories
    UserRepository,
    RefreshTokenRepository,

    // Business Logic Services
    AuthService,
    JwtTokenService,
    PasswordService,

    // Authentication Strategies
    JwtStrategy,
    LocalStrategy,

    // Guards
    JwtAuthGuard,
    RolesGuard,
    GrpcExceptionFilter,
    GrpcValidationPipe,
  ],
  exports: [
    // Export services for use in other modules
    AuthService,
    JwtTokenService,
    PasswordService,
    UserRepository,
    RefreshTokenRepository,
    JwtAuthGuard,
    RolesGuard,
  ],
})
export class AuthModule {
  configure(consumer: MiddlewareConsumer) {
    // Add pino-http middleware for HTTP request logging
    // Use the same logger instance as the main application to prevent duplicates
    consumer
      .apply(
        pinoHttp({
          logger,
          genReqId: (req: any) => {
            // Use existing request ID or generate new one
            return req.headers['x-request-id'] || uuidv4();
          },
          customLogLevel: (res: any, err: any) => {
            if (res.statusCode >= 400 && res.statusCode < 500) {
              return 'warn';
            } else if (res.statusCode >= 500 || err) {
              return 'error';
            }
            return 'info';
          },
          customSuccessMessage: (res: any) => {
            if (res.req && res.req.method) {
              return `${res.req.method} ${res.req.url} - ${res.statusCode}`;
            }
            return `gRPC call OK (${res.statusCode})`;
          },
          customErrorMessage: (error: any, res: any) => {
            if (res.req && res.req.method) {
              return `${res.req.method} ${res.req.url} - ${res.statusCode} - ${error.message}`;
            }
            return `gRPC call ERROR (${res.statusCode}) - ${error.message}`;
          },
          // Redact sensitive data from request/response logging
          redact: {
            paths: [
              'req.headers.authorization',
              'req.body.password',
              'req.body.currentPassword',
              'req.body.newPassword',
              'res.body.tokens',
              'res.body.accessToken',
              'res.body.refreshToken',
            ],
            remove: true,
          },
          // Custom serializers for auth-specific data
          serializers: {
            req: (req: any) => ({
              method: req.method,
              url: req.url,
              headers: {
                host: req.headers.host,
                'user-agent': req.headers['user-agent'],
                'content-type': req.headers['content-type'],
                'x-forwarded-for': req.headers['x-forwarded-for'],
                'x-real-ip': req.headers['x-real-ip'],
              },
              remoteAddress: req.connection?.remoteAddress,
              remotePort: req.connection?.remotePort,
            }),
            res: (res: any) => {
              // Skip serialization for gRPC responses (no getHeader method)
              if (typeof res.getHeader !== 'function') {
                return { statusCode: res.statusCode || 'unknown' };
              }
              // HTTP response serialization
              return {
                statusCode: res.statusCode,
                headers: {
                  'content-type': res.getHeader('content-type'),
                  'content-length': res.getHeader('content-length'),
                },
              };
            },
          },
        })
      )
      .forRoutes({ path: '*', method: RequestMethod.ALL });
  }
} 
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD, APP_FILTER } from '@nestjs/core';
import { AuthModule } from './presentation/auth/auth.module';
import { HealthController } from './presentation/health/health.controller';
import { getDatabaseConfig } from './infrastructure/database/database.config';
import { GrpcExceptionFilter } from './presentation/auth/filters/grpc-exception.filter';
import { validateEnvironment } from './config/environment.validation';
import { extendedThrottlerConfig } from './config/throttler.config';

@Module({
  imports: [
    // Global configuration with validation
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env.local', '.env'],
      cache: true,
      validate: validateEnvironment,
    }),

    // Rate limiting configuration with auth-specific limits
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => extendedThrottlerConfig,
      inject: [ConfigService],
    }),

    // Database connection
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: getDatabaseConfig,
      inject: [ConfigService],
    }),

    // Auth module with all authentication features
    AuthModule,
  ],
  controllers: [HealthController],
  providers: [
    // Apply throttling globally
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    // Apply global exception filter
    {
      provide: APP_FILTER,
      useClass: GrpcExceptionFilter,
    },
  ],
})
export class AppModule {} 
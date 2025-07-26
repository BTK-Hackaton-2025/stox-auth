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

@Module({
  imports: [
    // Global configuration with validation
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env.local', '.env'],
      cache: true,
      validate: validateEnvironment,
    }),

    // Rate limiting configuration
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => [
        {
          name: 'short',
          ttl: 1000, // 1 second
          limit: 3, // 3 requests per second
        },
        {
          name: 'medium',
          ttl: 10000, // 10 seconds  
          limit: 20, // 20 requests per 10 seconds
        },
        {
          name: 'long',
          ttl: 60000, // 1 minute
          limit: 100, // 100 requests per minute
        },
      ],
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
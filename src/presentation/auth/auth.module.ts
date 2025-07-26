import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';

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
export class AuthModule {} 
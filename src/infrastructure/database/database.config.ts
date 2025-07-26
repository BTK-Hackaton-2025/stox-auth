import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { User } from './entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';

export const getDatabaseConfig = (configService: ConfigService): TypeOrmModuleOptions => {
  const isProduction = configService.get('NODE_ENV') === 'production';

  return {
    type: 'postgres',
    host: configService.get<string>('DB_HOST') || 'localhost',
    port: configService.get<number>('DB_PORT') || 5432,
    username: configService.get<string>('DB_USERNAME') || 'postgres',
    password: configService.get<string>('DB_PASSWORD') || 'password',
    database: configService.get<string>('DB_NAME') || 'stox_auth',
    entities: [User, RefreshToken],
    synchronize: !isProduction, // Never use in production
    logging: !isProduction,
    ssl: isProduction ? { rejectUnauthorized: false } : false,
    migrations: ['dist/infrastructure/database/migrations/*.js'],
    migrationsRun: false, // Run migrations manually
    dropSchema: false,
    cache: {
      duration: 30000, // 30 seconds
    },
    extra: {
      // Connection pool settings
      max: configService.get<number>('DB_MAX_CONNECTIONS') || 10,
      min: configService.get<number>('DB_MIN_CONNECTIONS') || 1,
      acquire: 30000,
      idle: 10000,
    },
  };
}; 
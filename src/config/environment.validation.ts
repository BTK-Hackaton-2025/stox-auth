import { 
  IsString, 
  IsNumber, 
  IsOptional, 
  IsIn, 
  IsUrl,
  MinLength,
  Min,
  Max,
  validateSync,
} from 'class-validator';
import { plainToClass, Transform } from 'class-transformer';

export class EnvironmentVariables {
  // Database Configuration
  @IsString({ message: 'DB_HOST must be a string' })
  @IsOptional()
  DB_HOST: string = 'localhost';

  @IsNumber({}, { message: 'DB_PORT must be a number' })
  @Min(1, { message: 'DB_PORT must be greater than 0' })
  @Max(65535, { message: 'DB_PORT must be less than 65536' })
  @Transform(({ value }) => parseInt(value, 10))
  @IsOptional()
  DB_PORT: number = 5432;

  @IsString({ message: 'DB_USERNAME must be a string' })
  @IsOptional()
  DB_USERNAME: string = 'postgres';

  @IsString({ message: 'DB_PASSWORD must be a string' })
  @IsOptional()
  DB_PASSWORD: string = 'password';

  @IsString({ message: 'DB_NAME must be a string' })
  @IsOptional()
  DB_NAME: string = 'stox_auth';

  @IsNumber({}, { message: 'DB_MAX_CONNECTIONS must be a number' })
  @Min(1, { message: 'DB_MAX_CONNECTIONS must be at least 1' })
  @Transform(({ value }) => parseInt(value, 10))
  @IsOptional()
  DB_MAX_CONNECTIONS: number = 10;

  @IsNumber({}, { message: 'DB_MIN_CONNECTIONS must be a number' })
  @Min(0, { message: 'DB_MIN_CONNECTIONS must be at least 0' })
  @Transform(({ value }) => parseInt(value, 10))
  @IsOptional()
  DB_MIN_CONNECTIONS: number = 1;

  // JWT Configuration
  @IsString({ message: 'JWT_ACCESS_SECRET must be a string' })
  @MinLength(32, { message: 'JWT_ACCESS_SECRET must be at least 32 characters long' })
  JWT_ACCESS_SECRET!: string;

  @IsString({ message: 'JWT_REFRESH_SECRET must be a string' })
  @MinLength(32, { message: 'JWT_REFRESH_SECRET must be at least 32 characters long' })
  JWT_REFRESH_SECRET!: string;

  @IsString({ message: 'JWT_ACCESS_EXPIRES_IN must be a string' })
  @IsOptional()
  JWT_ACCESS_EXPIRES_IN: string = '15m';

  @IsString({ message: 'JWT_REFRESH_EXPIRES_IN must be a string' })
  @IsOptional()
  JWT_REFRESH_EXPIRES_IN: string = '7d';

  // Server Configuration
  @IsString({ message: 'NODE_ENV must be a string' })
  @IsIn(['development', 'production', 'test'], { 
    message: 'NODE_ENV must be one of: development, production, test' 
  })
  @IsOptional()
  NODE_ENV: string = 'development';

  @IsString({ message: 'GRPC_HOST must be a string' })
  @IsOptional()
  GRPC_HOST: string = '0.0.0.0';

  @IsNumber({}, { message: 'GRPC_PORT must be a number' })
  @Min(1, { message: 'GRPC_PORT must be greater than 0' })
  @Max(65535, { message: 'GRPC_PORT must be less than 65536' })
  @Transform(({ value }) => parseInt(value, 10))
  @IsOptional()
  GRPC_PORT: number = 50051;

  @IsNumber({}, { message: 'HTTP_PORT must be a number' })
  @Min(1, { message: 'HTTP_PORT must be greater than 0' })
  @Max(65535, { message: 'HTTP_PORT must be less than 65536' })
  @Transform(({ value }) => parseInt(value, 10))
  @IsOptional()
  HTTP_PORT: number = 3000;

  // Optional Email Configuration (for future email verification features)
  @IsString({ message: 'SMTP_HOST must be a string' })
  @IsOptional()
  SMTP_HOST?: string;

  @IsNumber({}, { message: 'SMTP_PORT must be a number' })
  @Transform(({ value }) => parseInt(value, 10))
  @IsOptional()
  SMTP_PORT?: number;

  @IsString({ message: 'SMTP_USER must be a string' })
  @IsOptional()
  SMTP_USER?: string;

  @IsString({ message: 'SMTP_PASS must be a string' })
  @IsOptional()
  SMTP_PASS?: string;

  @IsString({ message: 'FROM_EMAIL must be a string' })
  @IsOptional()
  FROM_EMAIL?: string;
}

export function validateEnvironment(config: Record<string, unknown>): EnvironmentVariables {
  const validatedConfig = plainToClass(EnvironmentVariables, config, {
    enableImplicitConversion: true,
  });

  const errors = validateSync(validatedConfig, {
    skipMissingProperties: false,
  });

  if (errors.length > 0) {
    const errorMessages = errors.map(error => {
      const constraints = Object.values(error.constraints || {});
      return `${error.property}: ${constraints.join(', ')}`;
    });

    throw new Error(
      `❌ Environment validation failed:\n${errorMessages.join('\n')}\n\n` +
      '💡 Please check your .env file and ensure all required environment variables are set correctly.'
    );
  }

  return validatedConfig;
} 
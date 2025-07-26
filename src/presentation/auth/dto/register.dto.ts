import { 
  IsEmail, 
  IsString, 
  MinLength, 
  MaxLength, 
  IsOptional, 
  IsEnum,
  Matches,
  IsNotEmpty,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { UserRole } from '../../../infrastructure/database/entities/user.entity';

export class RegisterDto {
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @Transform(({ value }) => value?.toLowerCase().trim())
  @IsNotEmpty({ message: 'Email is required' })
  email!: string;

  @IsString({ message: 'Password must be a string' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(128, { message: 'Password must not exceed 128 characters' })
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
    { 
      message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character' 
    }
  )
  @IsNotEmpty({ message: 'Password is required' })
  password!: string;

  @IsString({ message: 'First name must be a string' })
  @MinLength(1, { message: 'First name cannot be empty' })
  @MaxLength(100, { message: 'First name must not exceed 100 characters' })
  @Transform(({ value }) => value?.trim())
  @IsNotEmpty({ message: 'First name is required' })
  firstName!: string;

  @IsString({ message: 'Last name must be a string' })
  @MinLength(1, { message: 'Last name cannot be empty' })
  @MaxLength(100, { message: 'Last name must not exceed 100 characters' })
  @Transform(({ value }) => value?.trim())
  @IsNotEmpty({ message: 'Last name is required' })
  lastName!: string;

  @IsOptional()
  @IsEnum(UserRole, { message: 'Role must be one of: admin, user, moderator' })
  role?: UserRole;
} 
import { 
  IsString, 
  MinLength, 
  MaxLength, 
  IsNotEmpty,
  Matches,
} from 'class-validator';

export class ChangePasswordDto {
  @IsString({ message: 'Current password must be a string' })
  @IsNotEmpty({ message: 'Current password is required' })
  currentPassword!: string;

  @IsString({ message: 'New password must be a string' })
  @MinLength(8, { message: 'New password must be at least 8 characters long' })
  @MaxLength(128, { message: 'New password must not exceed 128 characters' })
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
    { 
      message: 'New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character' 
    }
  )
  @IsNotEmpty({ message: 'New password is required' })
  newPassword!: string;
} 
import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class PasswordService {
  private readonly saltRounds: number;

  constructor(private readonly configService: ConfigService) {
    // bcrypt configuration - can be overridden via environment variables
    this.saltRounds = this.configService.get<number>('BCRYPT_SALT_ROUNDS') || 12;
  }

  /**
   * Hash a password using bcrypt
   */
  async hashPassword(password: string): Promise<string> {
    try {
      const hashedPassword = await bcrypt.hash(password, this.saltRounds);
      return hashedPassword;
    } catch (error) {
      throw new Error(`Failed to hash password: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Verify a password against its hash
   */
  async verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
    try {
      return await bcrypt.compare(password, hashedPassword);
    } catch (error) {
      // If verification fails due to invalid hash format or other errors,
      // we should return false rather than throwing an error
      return false;
    }
  }

  /**
   * Check if password meets security requirements
   */
  validatePasswordStrength(password: string): {
    isValid: boolean;
    errors: string[];
    score: number;
  } {
    const errors: string[] = [];
    let score = 0;

    // Minimum length check
    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    } else if (password.length >= 12) {
      score += 2;
    } else {
      score += 1;
    }

    // Uppercase letter check
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    } else {
      score += 1;
    }

    // Lowercase letter check
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    } else {
      score += 1;
    }

    // Digit check
    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one digit');
    } else {
      score += 1;
    }

    // Special character check
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('Password must contain at least one special character');
    } else {
      score += 2;
    }

    // Check for common patterns
    if (/(.)\1{2,}/.test(password)) {
      errors.push('Password should not contain repeated characters');
      score -= 1;
    }

    // Check for sequential characters
    if (this.hasSequentialCharacters(password)) {
      errors.push('Password should not contain sequential characters');
      score -= 1;
    }

    // Common password check (basic)
    if (this.isCommonPassword(password)) {
      errors.push('Password is too common, please choose a more unique password');
      score -= 2;
    }

    return {
      isValid: errors.length === 0,
      errors,
      score: Math.max(0, score), // Ensure score is not negative
    };
  }

  /**
   * Check if password needs rehashing (if bcrypt salt rounds have changed)
   */
  async needsRehash(hashedPassword: string): Promise<boolean> {
    try {
      // Extract salt rounds from existing hash
      const existingSaltRounds = this.getSaltRoundsFromHash(hashedPassword);
      
      // Compare with current configuration
      return existingSaltRounds !== this.saltRounds;
    } catch {
      // If we can't determine salt rounds, assume it needs rehash
      return true;
    }
  }

  /**
   * Extract salt rounds from bcrypt hash
   */
  private getSaltRoundsFromHash(hash: string): number {
    try {
      // bcrypt hash format: $2b$[cost]$[salt][hash]
      const parts = hash.split('$');
      if (parts.length >= 3) {
        return parseInt(parts[2], 10);
      }
      throw new Error('Invalid hash format');
    } catch {
      // Default to 10 if we can't parse (common bcrypt default)
      return 10;
    }
  }

  /**
   * Generate a secure random password
   */
  generateSecurePassword(length: number = 16): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let password = '';

    // Ensure at least one character from each required category
    password += this.getRandomChar('ABCDEFGHIJKLMNOPQRSTUVWXYZ'); // Uppercase
    password += this.getRandomChar('abcdefghijklmnopqrstuvwxyz'); // Lowercase
    password += this.getRandomChar('0123456789'); // Digit
    password += this.getRandomChar('!@#$%^&*()_+-=[]{}|;:,.<>?'); // Special

    // Fill the rest with random characters
    for (let i = password.length; i < length; i++) {
      password += this.getRandomChar(charset);
    }

    // Shuffle the password to avoid predictable patterns
    return this.shuffleString(password);
  }

  /**
   * Check if password contains sequential characters
   */
  private hasSequentialCharacters(password: string): boolean {
    const sequences = [
      'abcdefghijklmnopqrstuvwxyz',
      'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      '0123456789',
      'qwertyuiop',
      'asdfghjkl',
      'zxcvbnm',
    ];

    for (const sequence of sequences) {
      for (let i = 0; i <= sequence.length - 3; i++) {
        const subSeq = sequence.substring(i, i + 3);
        if (password.toLowerCase().includes(subSeq)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Check if password is in common passwords list (basic implementation)
   */
  private isCommonPassword(password: string): boolean {
    const commonPasswords = [
      'password', '123456', '123456789', 'qwerty', 'abc123',
      'password123', 'admin', 'letmein', 'welcome', 'monkey',
      'dragon', 'master', 'hello', 'password1', '123123',
    ];

    return commonPasswords.includes(password.toLowerCase());
  }

  /**
   * Get random character from charset
   */
  private getRandomChar(charset: string): string {
    return charset.charAt(Math.floor(Math.random() * charset.length));
  }

  /**
   * Shuffle string characters
   */
  private shuffleString(str: string): string {
    const arr = str.split('');
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr.join('');
  }

  /**
   * Get password strength description
   */
  getPasswordStrengthDescription(score: number): string {
    if (score <= 2) return 'Very Weak';
    if (score <= 4) return 'Weak';
    if (score <= 6) return 'Fair';
    if (score <= 8) return 'Good';
    return 'Strong';
  }
} 
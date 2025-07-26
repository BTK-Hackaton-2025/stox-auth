import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
  MODERATOR = 'moderator',
}

@Entity('users')
@Index(['email'], { unique: true })
export class User {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'varchar', length: 255, unique: true })
  email!: string;

  @Column({ type: 'varchar', length: 255 })
  passwordHash!: string;

  @Column({ type: 'varchar', length: 100 })
  firstName!: string;

  @Column({ type: 'varchar', length: 100 })
  lastName!: string;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.USER,
  })
  role!: UserRole;

  @Column({ type: 'boolean', default: true })
  isActive!: boolean;

  @Column({ type: 'boolean', default: false })
  isEmailVerified!: boolean;

  @Column({ type: 'varchar', length: 255, nullable: true })
  emailVerificationToken!: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  passwordResetToken!: string;

  @Column({ type: 'timestamp', nullable: true })
  passwordResetExpires!: Date;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt!: Date;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;

  // Virtual properties for full name
  get fullName(): string {
    return `${this.firstName} ${this.lastName}`;
  }

  // Method to convert to safe object (without sensitive data)
  toSafeObject() {
    const { passwordHash, passwordResetToken, emailVerificationToken, ...safeUser } = this;
    return safeUser;
  }
} 
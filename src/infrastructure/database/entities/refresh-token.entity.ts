import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { User } from './user.entity';

@Entity('refresh_tokens')
@Index(['token'], { unique: true })
@Index(['userId'])
export class RefreshToken {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'text', unique: true })
  token!: string;

  @Column({ type: 'uuid' })
  userId!: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user!: User;

  @Column({ type: 'timestamp' })
  expiresAt!: Date;

  @Column({ type: 'boolean', default: false })
  isRevoked!: boolean;

  @Column({ type: 'varchar', length: 255, nullable: true })
  revokedReason!: string;

  @Column({ type: 'timestamp', nullable: true })
  revokedAt!: Date;

  @Column({ type: 'inet', nullable: true })
  ipAddress!: string;

  @Column({ type: 'text', nullable: true })
  userAgent!: string;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;

  // Check if token is expired
  isExpired(): boolean {
    return new Date() > this.expiresAt;
  }

  // Check if token is valid (not expired and not revoked)
  isValid(): boolean {
    return !this.isExpired() && !this.isRevoked;
  }

  // Revoke the token
  revoke(reason?: string): void {
    this.isRevoked = true;
    this.revokedAt = new Date();
    this.revokedReason = reason || 'Manually revoked';
  }
} 
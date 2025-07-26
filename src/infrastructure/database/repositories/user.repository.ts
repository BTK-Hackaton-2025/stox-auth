import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, FindOptionsWhere } from 'typeorm';
import { User, UserRole } from '../entities/user.entity';

export interface CreateUserData {
  email: string;
  passwordHash: string;
  firstName: string;
  lastName: string;
  role?: UserRole;
}

export interface UpdateUserData {
  firstName?: string;
  lastName?: string;
  email?: string;
  role?: UserRole;
  isActive?: boolean;
  isEmailVerified?: boolean;
  emailVerificationToken?: string;
  passwordResetToken?: string;
  passwordResetExpires?: Date;
  lastLoginAt?: Date;
}

@Injectable()
export class UserRepository {
  constructor(
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
  ) {}

  async create(userData: CreateUserData): Promise<User> {
    const user = this.userRepo.create(userData);
    return await this.userRepo.save(user);
  }

  async findById(id: string): Promise<User | null> {
    return await this.userRepo.findOne({
      where: { id },
    });
  }

  async findByEmail(email: string): Promise<User | null> {
    return await this.userRepo.findOne({
      where: { email: email.toLowerCase() },
    });
  }

  async findByEmailVerificationToken(token: string): Promise<User | null> {
    return await this.userRepo.findOne({
      where: { emailVerificationToken: token },
    });
  }

  async findByPasswordResetToken(token: string): Promise<User | null> {
    return await this.userRepo.findOne({
      where: { 
        passwordResetToken: token,
      },
    });
  }

  async update(id: string, updateData: UpdateUserData): Promise<User | null> {
    await this.userRepo.update(id, updateData);
    return await this.findById(id);
  }

  async updatePassword(id: string, passwordHash: string): Promise<void> {
    await this.userRepo.update(id, { 
      passwordHash,
      passwordResetToken: undefined,
      passwordResetExpires: undefined,
    });
  }

  async updateLastLoginAt(id: string): Promise<void> {
    await this.userRepo.update(id, { 
      lastLoginAt: new Date(),
    });
  }

  async delete(id: string): Promise<void> {
    await this.userRepo.delete(id);
  }

  async findAll(options?: {
    isActive?: boolean;
    role?: UserRole;
    limit?: number;
    offset?: number;
  }): Promise<User[]> {
    const where: FindOptionsWhere<User> = {};
    
    if (options?.isActive !== undefined) {
      where.isActive = options.isActive;
    }
    
    if (options?.role) {
      where.role = options.role;
    }

    return await this.userRepo.find({
      where,
      take: options?.limit,
      skip: options?.offset,
      order: { createdAt: 'DESC' },
    });
  }

  async count(options?: {
    isActive?: boolean;
    role?: UserRole;
  }): Promise<number> {
    const where: FindOptionsWhere<User> = {};
    
    if (options?.isActive !== undefined) {
      where.isActive = options.isActive;
    }
    
    if (options?.role) {
      where.role = options.role;
    }

    return await this.userRepo.count({ where });
  }

  async exists(email: string): Promise<boolean> {
    const count = await this.userRepo.count({
      where: { email: email.toLowerCase() },
    });
    return count > 0;
  }

  async deactivate(id: string): Promise<void> {
    await this.userRepo.update(id, { isActive: false });
  }

  async activate(id: string): Promise<void> {
    await this.userRepo.update(id, { isActive: true });
  }

  async verifyEmail(id: string): Promise<void> {
    await this.userRepo.update(id, { 
      isEmailVerified: true,
      emailVerificationToken: undefined,
    });
  }
} 
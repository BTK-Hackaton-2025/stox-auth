import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { RefreshToken } from '../entities/refresh-token.entity';

export interface CreateRefreshTokenData {
  token: string;
  userId: string;
  expiresAt: Date;
  ipAddress?: string;
  userAgent?: string;
}

@Injectable()
export class RefreshTokenRepository {
  constructor(
    @InjectRepository(RefreshToken)
    private readonly refreshTokenRepo: Repository<RefreshToken>,
  ) {}

  async create(tokenData: CreateRefreshTokenData): Promise<RefreshToken> {
    const refreshToken = this.refreshTokenRepo.create(tokenData);
    return await this.refreshTokenRepo.save(refreshToken);
  }

  async findByToken(token: string): Promise<RefreshToken | null> {
    return await this.refreshTokenRepo.findOne({
      where: { token },
      relations: ['user'],
    });
  }

  async findValidByToken(token: string): Promise<RefreshToken | null> {
    return await this.refreshTokenRepo.findOne({
      where: { 
        token,
        isRevoked: false,
      },
      relations: ['user'],
    });
  }

  async findByUserId(userId: string): Promise<RefreshToken[]> {
    return await this.refreshTokenRepo.find({
      where: { userId },
      order: { createdAt: 'DESC' },
    });
  }

  async findValidByUserId(userId: string): Promise<RefreshToken[]> {
    return await this.refreshTokenRepo.find({
      where: { 
        userId,
        isRevoked: false,
      },
      order: { createdAt: 'DESC' },
    });
  }

  async revokeToken(token: string, reason?: string): Promise<void> {
    const refreshToken = await this.findByToken(token);
    if (refreshToken) {
      refreshToken.revoke(reason);
      await this.refreshTokenRepo.save(refreshToken);
    }
  }

  async revokeAllUserTokens(userId: string, reason?: string): Promise<void> {
    const tokens = await this.findValidByUserId(userId);
    
    for (const token of tokens) {
      token.revoke(reason);
    }
    
    if (tokens.length > 0) {
      await this.refreshTokenRepo.save(tokens);
    }
  }

  async revokeById(id: string, reason?: string): Promise<void> {
    const refreshToken = await this.refreshTokenRepo.findOne({
      where: { id },
    });
    
    if (refreshToken) {
      refreshToken.revoke(reason);
      await this.refreshTokenRepo.save(refreshToken);
    }
  }

  async deleteExpiredTokens(): Promise<number> {
    const result = await this.refreshTokenRepo.delete({
      expiresAt: LessThan(new Date()),
    });
    
    return result.affected || 0;
  }

  async deleteRevokedTokens(): Promise<number> {
    const result = await this.refreshTokenRepo.delete({
      isRevoked: true,
    });
    
    return result.affected || 0;
  }

  async deleteUserTokens(userId: string): Promise<number> {
    const result = await this.refreshTokenRepo.delete({
      userId,
    });
    
    return result.affected || 0;
  }

  async countUserTokens(userId: string): Promise<number> {
    return await this.refreshTokenRepo.count({
      where: { 
        userId,
        isRevoked: false,
      },
    });
  }

  async countValidUserTokens(userId: string): Promise<number> {
    const now = new Date();
    return await this.refreshTokenRepo
      .createQueryBuilder('token')
      .where('token.userId = :userId', { userId })
      .andWhere('token.isRevoked = false')
      .andWhere('token.expiresAt > :now', { now })
      .getCount();
  }

  async cleanupExpiredTokens(): Promise<number> {
    // Delete tokens that are expired for more than 7 days
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const result = await this.refreshTokenRepo.delete({
      expiresAt: LessThan(sevenDaysAgo),
    });
    
    return result.affected || 0;
  }

  async getTokenStatistics(userId?: string) {
    const query = this.refreshTokenRepo.createQueryBuilder('token');
    
    if (userId) {
      query.where('token.userId = :userId', { userId });
    }
    
    const [
      total,
      valid,
      expired,
      revoked,
    ] = await Promise.all([
      query.clone().getCount(),
      query.clone().andWhere('token.isRevoked = false').andWhere('token.expiresAt > :now', { now: new Date() }).getCount(),
      query.clone().andWhere('token.expiresAt <= :now', { now: new Date() }).getCount(),
      query.clone().andWhere('token.isRevoked = true').getCount(),
    ]);
    
    return {
      total,
      valid,
      expired,
      revoked,
    };
  }
} 
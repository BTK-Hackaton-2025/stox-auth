import { Controller, Get } from '@nestjs/common';
import { Public } from '../auth/decorators/public.decorator';

@Controller()
export class HealthController {
  @Public()
  @Get('health')
  getHealth() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      service: 'stox-auth-microservice',
      version: '1.0.0',
      uptime: process.uptime(),
    };
  }

  @Public()
  @Get('health/ready')
  getReadiness() {
    return {
      status: 'ready',
      timestamp: new Date().toISOString(),
    };
  }

  @Public()
  @Get('health/live')
  getLiveness() {
    return {
      status: 'alive',
      timestamp: new Date().toISOString(),
    };
  }

  @Public()
  @Get()
  getRoot() {
    return {
      message: 'NestJS gRPC Authentication Microservice',
      status: 'running',
      endpoints: {
        health: '/health',
        readiness: '/health/ready',
        liveness: '/health/live',
      },
      grpc: {
        host: process.env.GRPC_HOST || '0.0.0.0',
        port: process.env.GRPC_PORT || 50051,
      },
    };
  }
} 
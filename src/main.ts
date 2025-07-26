import { NestFactory } from '@nestjs/core';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe, Logger } from '@nestjs/common';
import { join } from 'path';
import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger('Bootstrap');

  try {
    // Create NestJS application
    const app = await NestFactory.create(AppModule, {
      logger: ['error', 'warn', 'log', 'debug', 'verbose'],
    });

    // Get configuration service
    const configService = app.get(ConfigService);

    // Enable global validation pipe
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
        transformOptions: {
          enableImplicitConversion: true,
        },
      }),
    );

    // Configure gRPC microservice
    const grpcOptions: MicroserviceOptions = {
      transport: Transport.GRPC,
      options: {
        package: 'auth',
        protoPath: join(process.cwd(), 'src/proto/auth.proto'),
        url: `${configService.get('GRPC_HOST', '0.0.0.0')}:${configService.get('GRPC_PORT', 50051)}`,
        loader: {
          keepCase: true,
          longs: String,
          enums: String,
          defaults: true,
          oneofs: true,
        },
        maxSendMessageLength: 1024 * 1024 * 4, // 4MB
        maxReceiveMessageLength: 1024 * 1024 * 4, // 4MB
      },
    };

    // Connect gRPC microservice
    app.connectMicroservice<MicroserviceOptions>(grpcOptions);

    // Start all microservices
    await app.startAllMicroservices();
    logger.log(`🚀 gRPC Auth Microservice is running on ${grpcOptions.options.url}`);

    // Optionally start HTTP server for health checks
    const httpPort = configService.get('HTTP_PORT', 3000);
    await app.listen(httpPort);
    logger.log(`🔧 HTTP Health Check server is running on port ${httpPort}`);

    // Graceful shutdown
    process.on('SIGTERM', async () => {
      logger.log('SIGTERM received, shutting down gracefully');
      await app.close();
      process.exit(0);
    });

    process.on('SIGINT', async () => {
      logger.log('SIGINT received, shutting down gracefully');
      await app.close();
      process.exit(0);
    });

  } catch (error) {
    logger.error(`Failed to start application: ${error instanceof Error ? error.message : 'Unknown error'}`, error instanceof Error ? error.stack : undefined);
    process.exit(1);
  }
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  const logger = new Logger('UnhandledRejection');
  logger.error('Unhandled Promise Rejection:', reason);
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  const logger = new Logger('UncaughtException');
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

bootstrap(); 
import { NestFactory } from '@nestjs/core';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';
import { join } from 'path';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { logger, PinoLoggerService } from './config/logger.config';

async function bootstrap() {
  try {
    logger.info({
      event: 'application_startup',
      nodeEnv: process.env.NODE_ENV,
      nodeVersion: process.version,
    }, 'Starting Stox Auth Microservice');

    // Create NestJS application with pino logger
    const app = await NestFactory.create(AppModule, {
      logger: false, // Disable default logger, we'll use pino
      bufferLogs: true,
    });

    // Use pino as the application logger
    app.useLogger(new PinoLoggerService());

    // Add security headers for HTTP endpoints
    app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
      crossOriginEmbedderPolicy: false, // Allow for development/testing
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      },
    }));

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
    logger.info({
      event: 'grpc_server_started',
      url: grpcOptions.options.url,
      package: 'auth',
      protoPath: grpcOptions.options.protoPath,
    }, '🚀 gRPC Auth Microservice is running');

    // Optionally start HTTP server for health checks
    const httpPort = configService.get('HTTP_PORT', 5051);
    await app.listen(httpPort);
    logger.info({
      event: 'http_server_started',
      port: httpPort,
      purpose: 'health_checks',
    }, '🔧 HTTP Health Check server is running');

    // Graceful shutdown
    process.on('SIGTERM', async () => {
      logger.info({
        event: 'application_shutdown',
        signal: 'SIGTERM',
      }, 'SIGTERM received, shutting down gracefully');
      await app.close();
      process.exit(0);
    });

    process.on('SIGINT', async () => {
      logger.info({
        event: 'application_shutdown',
        signal: 'SIGINT',
      }, 'SIGINT received, shutting down gracefully');
      await app.close();
      process.exit(0);
    });

  } catch (error) {
    logger.error({
      event: 'application_startup_failed',
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
    }, 'Failed to start application');
    process.exit(1);
  }
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.fatal({
    event: 'unhandled_promise_rejection',
    reason: reason instanceof Error ? reason.message : String(reason),
    stack: reason instanceof Error ? reason.stack : undefined,
    promise: String(promise),
  }, 'Unhandled Promise Rejection - shutting down');
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.fatal({
    event: 'uncaught_exception',
    error: error.message,
    stack: error.stack,
    name: error.name,
  }, 'Uncaught Exception - shutting down');
  process.exit(1);
});

bootstrap(); 
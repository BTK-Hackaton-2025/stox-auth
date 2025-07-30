import { 
  PipeTransform, 
  Injectable, 
  ArgumentMetadata, 
  BadRequestException,
} from '@nestjs/common';
import { validate, ValidationError } from 'class-validator';
import { plainToClass } from 'class-transformer';
import { logger } from '../../../config/logger.config';

@Injectable()
export class GrpcValidationPipe implements PipeTransform<any> {
  async transform(value: any, { metatype }: ArgumentMetadata) {
    // Skip validation if no metatype or it's a native type
    if (!metatype || !this.toValidate(metatype)) {
      return value;
    }

    logger.debug({
      event: 'validation_start',
      dtoType: metatype.name,
      hasValue: !!value,
      valueKeys: value ? Object.keys(value) : [],
    }, '🔍 Starting validation');

    // Transform plain object to class instance
    const object = plainToClass(metatype, value);
    
    // Validate the object
    const errors = await validate(object, {
      whitelist: true, // Strip properties that don't have decorators
      forbidNonWhitelisted: true, // Throw error if non-whitelisted properties exist
      transform: true, // Transform the object using @Transform decorators
      transformOptions: {
        enableImplicitConversion: true,
      },
    });

    if (errors.length > 0) {
      const errorMessages = this.formatValidationErrors(errors);
      
      logger.warn({
        event: 'validation_failed',
        dtoType: metatype.name,
        errorCount: errors.length,
        errors: errorMessages,
        valueKeys: value ? Object.keys(value) : [],
      }, '❌ Validation failed');

      throw new BadRequestException({
        message: 'Validation failed',
        errors: errorMessages,
      });
    }

    logger.debug({
      event: 'validation_success',
      dtoType: metatype.name,
    }, '✅ Validation passed');

    return object;
  }

  private toValidate(metatype: Function): boolean {
    const types: Function[] = [String, Boolean, Number, Array, Object];
    return !types.includes(metatype);
  }

  private formatValidationErrors(errors: ValidationError[]): string[] {
    const messages: string[] = [];

    const processError = (error: ValidationError, parentPath = '') => {
      const currentPath = parentPath ? `${parentPath}.${error.property}` : error.property;

      // Add constraint messages for current property
      if (error.constraints) {
        Object.values(error.constraints).forEach(message => {
          messages.push(`${currentPath}: ${message}`);
        });
      }

      // Process nested errors recursively
      if (error.children && error.children.length > 0) {
        error.children.forEach(childError => {
          processError(childError, currentPath);
        });
      }
    };

    errors.forEach(error => processError(error));
    return messages;
  }
} 
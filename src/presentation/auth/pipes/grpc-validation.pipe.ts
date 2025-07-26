import { 
  PipeTransform, 
  Injectable, 
  ArgumentMetadata, 
  BadRequestException,
} from '@nestjs/common';
import { validate, ValidationError } from 'class-validator';
import { plainToClass } from 'class-transformer';

@Injectable()
export class GrpcValidationPipe implements PipeTransform<any> {
  async transform(value: any, { metatype }: ArgumentMetadata) {
    // Skip validation if no metatype or it's a native type
    if (!metatype || !this.toValidate(metatype)) {
      return value;
    }

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
      throw new BadRequestException({
        message: 'Validation failed',
        errors: errorMessages,
      });
    }

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
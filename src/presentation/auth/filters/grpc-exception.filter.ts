import { 
  ExceptionFilter, 
  Catch, 
  ArgumentsHost, 
  HttpException, 
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { Observable, throwError } from 'rxjs';

export interface GrpcErrorResponse {
  success: boolean;
  message: string;
  errors: string[];
  code?: number;
}

@Catch()
export class GrpcExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GrpcExceptionFilter.name);

  catch(exception: any, host: ArgumentsHost): Observable<any> {
    const contextType = host.getType();
    
    if (contextType === 'rpc') {
      return this.handleGrpcException(exception, host);
    }
    
    // For HTTP context, let the default exception filter handle it
    throw exception;
  }

  private handleGrpcException(exception: any, host: ArgumentsHost): Observable<any> {
    const rpcContext = host.switchToRpc();
    const data = rpcContext.getData();
    
    // Log the actual error for debugging (server-side only)
    this.logger.error(
      `gRPC Error in ${rpcContext.getContext()?.constructor?.name || 'Unknown'}: ${exception.message}`,
      exception.stack,
    );

    // Determine the sanitized response based on exception type
    const errorResponse = this.mapExceptionToGrpcResponse(exception);
    
    // Return the sanitized error response
    return throwError(() => new RpcException(errorResponse));
  }

  private mapExceptionToGrpcResponse(exception: any): GrpcErrorResponse {
    // Default error response
    let response: GrpcErrorResponse = {
      success: false,
      message: 'Internal server error',
      errors: ['An unexpected error occurred'],
      code: HttpStatus.INTERNAL_SERVER_ERROR,
    };

    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const exceptionResponse = exception.getResponse();
      
      response.code = status;
      
      // Handle client errors (4xx) - these are safe to expose
      if (status >= 400 && status < 500) {
        if (typeof exceptionResponse === 'string') {
          response.message = exceptionResponse;
          response.errors = [exceptionResponse];
        } else if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
          const responseObj = exceptionResponse as any;
          response.message = responseObj.message || 'Client error';
          response.errors = Array.isArray(responseObj.errors) 
            ? responseObj.errors 
            : Array.isArray(responseObj.message)
            ? responseObj.message
            : [responseObj.message || 'Client error'];
        }
      } else {
        // Server errors (5xx) - sanitize the message
        response.message = 'Internal server error';
        response.errors = ['The server encountered an unexpected error'];
      }
    } else if (exception instanceof RpcException) {
      // Already an RPC exception, extract the error
      const error = exception.getError();
      if (typeof error === 'object' && error !== null) {
        response = { ...response, ...error as GrpcErrorResponse };
      } else {
        response.message = error.toString();
        response.errors = [error.toString()];
      }
    } else if (exception?.code === 'ECONNREFUSED' || exception?.code === 'ENOTFOUND') {
      // Database/external service connection errors
      response.message = 'Service temporarily unavailable';
      response.errors = ['Please try again later'];
      response.code = HttpStatus.SERVICE_UNAVAILABLE;
    } else if (exception?.name === 'ValidationError') {
      // Validation errors are safe to expose
      response.message = 'Validation failed';
      response.errors = exception.errors || ['Invalid input data'];
      response.code = HttpStatus.BAD_REQUEST;
    } else if (exception?.name === 'TokenExpiredError') {
      // JWT specific errors
      response.message = 'Token expired';
      response.errors = ['Authentication token has expired'];
      response.code = HttpStatus.UNAUTHORIZED;
    } else if (exception?.name === 'JsonWebTokenError') {
      response.message = 'Invalid token';
      response.errors = ['Authentication token is invalid'];
      response.code = HttpStatus.UNAUTHORIZED;
    } else {
      // Unknown errors - log but don't expose details
      this.logger.error('Unhandled exception type:', exception);
    }

    return response;
  }
} 
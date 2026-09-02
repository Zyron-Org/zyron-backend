import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { isArray } from 'class-validator';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();
    const request = ctx.getRequest();

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    if (exception instanceof HttpException) {
      const errResponse: any = exception.getResponse();

      const message =
        typeof errResponse === 'object' && errResponse.message
          ? isArray(errResponse.message)
            ? errResponse.message[0]
            : errResponse.message
          : exception.message;

      return response.status(status).json({
        status: 'error',
        statusCode: status,
        message,
        path: request.url,
        timestamp: new Date().toISOString(),
      });
    }

    // Unhandled 500 error
    console.error('Unhandled Exception:', exception);

    return response.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
      status: 'error',
      statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
      message: 'Internal server error occurred',
      path: request.url,
      timestamp: new Date().toISOString(),
    });
  }
}

import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { WinstonLoggerService } from './common/logger/winston-logger.service';

async function bootstrap() {
  try {
    const configService = new ConfigService();

    const app = await NestFactory.create(AppModule, {
      logger: new WinstonLoggerService(configService),
      abortOnError: false,
    });

    app.use(helmet());
    app.use(cookieParser());
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );

    const frontendOrigin = configService.get<string>('FRONTEND_ORIGIN');
    const allowCredentials = configService.get<string>('ALLOW_CREDENTIALS') === 'true';

    app.enableCors({
      origin: frontendOrigin,
      credentials: allowCredentials,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
    });

    const config = new DocumentBuilder()
      .setTitle('Authentication API')
      .setDescription('Full-stack authentication module API documentation')
      .setVersion('1.0')
      .addCookieAuth('access_token', {
        type: 'http',
        in: 'cookie',
        scheme: 'bearer',
      })
      .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api', app, document);

    const port = parseInt(process.env.PORT || configService.get<string>('PORT') || '8080', 10);
    await app.listen(port, '0.0.0.0');

    const logger = app.get(WinstonLoggerService);
    logger.log(`Application is running on: http://0.0.0.0:${port}`);
  } catch (error) {
    console.error('Failed to start application:', error);
    process.exit(1);
  }
}

bootstrap();

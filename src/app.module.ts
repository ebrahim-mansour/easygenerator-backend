import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard } from '@nestjs/throttler';
import { ConfigService } from '@nestjs/config';
import * as Joi from 'joi';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { WinstonLoggerService } from './common/logger/winston-logger.service';

const envValidationSchema = Joi.object({
  PORT: Joi.number().default(3000),
  MONGO_URI: Joi.string().required(),
  JWT_SECRET: Joi.string().required(),
  ACCESS_TOKEN_TTL: Joi.string().required(),
  REFRESH_TOKEN_TTL: Joi.string().required(),
  COOKIE_DOMAIN: Joi.string().required(),
  COOKIE_SECURE: Joi.string().valid('true', 'false').required(),
  COOKIE_SAMESITE: Joi.string().valid('strict', 'lax', 'none').default('lax'),
  FRONTEND_ORIGIN: Joi.string().uri().required(),
  ALLOW_CREDENTIALS: Joi.string().valid('true', 'false').required(),
  THROTTLE_TTL: Joi.number().default(60).positive(),
  THROTTLE_LIMIT: Joi.number().default(10).positive(),
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
});

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      validationSchema: envValidationSchema,
      validationOptions: {
        allowUnknown: true,
        abortEarly: false,
      },
    }),
    MongooseModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        uri: configService.get<string>('MONGO_URI'),
      }),
    }),
    ThrottlerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        throttlers: [{
          ttl: parseInt(configService.get<string>('THROTTLE_TTL', '60')),
          limit: parseInt(configService.get<string>('THROTTLE_LIMIT', '10')),
        }],
      }),
    }),
    AuthModule,
    UsersModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    WinstonLoggerService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}


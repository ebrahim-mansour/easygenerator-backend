import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { ConfigModule, ConfigService } from '@nestjs/config';
import cookieParser from 'cookie-parser';

describe('AuthController (e2e)', () => {
  let app: INestApplication;
  let mongoServer: MongoMemoryServer;
  let mongoUri: string;

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    mongoUri = mongoServer.getUri();

    process.env.MONGO_URI = mongoUri;
    process.env.JWT_SECRET = 'test-jwt-secret';
    process.env.ACCESS_TOKEN_TTL = '900';
    process.env.REFRESH_TOKEN_TTL = '1209600';
    process.env.COOKIE_DOMAIN = 'localhost';
    process.env.COOKIE_SECURE = 'false';
    process.env.COOKIE_SAMESITE = 'Lax';
    process.env.FRONTEND_ORIGIN = 'http://localhost:5173';
    process.env.ALLOW_CREDENTIALS = 'true';
    process.env.THROTTLE_TTL = '60';
    process.env.THROTTLE_LIMIT = '10';
    process.env.NODE_ENV = 'test';

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideModule(ConfigModule)
      .useModule(
        ConfigModule.forRoot({
          isGlobal: true,
          ignoreEnvFile: true, // Don't load .env file in tests
          validationSchema: undefined, // Skip validation in tests
        }),
      )
      .overrideProvider(ConfigService)
      .useValue({
        get: (key: string, defaultValue?: any) => {
          const envValue = process.env[key];
          if (envValue !== undefined) {
            // Convert string numbers to numbers for THROTTLE_TTL and THROTTLE_LIMIT
            if (key === 'THROTTLE_TTL' || key === 'THROTTLE_LIMIT') {
              return parseInt(envValue, 10);
            }
            return envValue;
          }
          return defaultValue;
        },
      })
      .compile();

    app = moduleFixture.createNestApplication();
    app.use(cookieParser());
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );

    try {
      await app.init();
    } catch (error) {
      console.error('Failed to initialize app:', error);
      throw error;
    }
  }, 600000);

  afterAll(async () => {
    if (app) {
      await app.close();
    }
    if (mongoServer) {
      await mongoServer.stop();
    }
  });

  describe('/auth/signup (POST)', () => {
    it('should create a new user', () => {
      return request(app.getHttpServer())
        .post('/auth/signup')
        .send({
          email: 'test@example.com',
          name: 'Test User',
          password: 'Password123!',
        })
        .expect(201)
        .expect((res) => {
          expect(res.body).toHaveProperty('message');
          expect(res.body).toHaveProperty('user');
          expect(res.body.user.email).toBe('test@example.com');
          expect(res.headers['set-cookie']).toBeDefined();
          const cookies = Array.isArray(res.headers['set-cookie'])
            ? res.headers['set-cookie']
            : [res.headers['set-cookie']];
          expect(cookies.some((cookie: string) => cookie.includes('access_token'))).toBe(true);
          expect(cookies.some((cookie: string) => cookie.includes('refresh_token'))).toBe(true);
        });
    });

    it('should reject duplicate email', async () => {
      await request(app.getHttpServer())
        .post('/auth/signup')
        .send({
          email: 'duplicate@example.com',
          name: 'First User',
          password: 'Password123!',
        })
        .expect(201);

      return request(app.getHttpServer())
        .post('/auth/signup')
        .send({
          email: 'duplicate@example.com',
          name: 'Second User',
          password: 'Password123!',
        })
        .expect(409);
    });

    it('should reject invalid email', () => {
      return request(app.getHttpServer())
        .post('/auth/signup')
        .send({
          email: 'invalid-email',
          name: 'Test User',
          password: 'Password123!',
        })
        .expect(400);
    });

    it('should reject short name', () => {
      return request(app.getHttpServer())
        .post('/auth/signup')
        .send({
          email: 'test@example.com',
          name: 'Ab',
          password: 'Password123!',
        })
        .expect(400);
    });

    it('should reject weak password', () => {
      return request(app.getHttpServer())
        .post('/auth/signup')
        .send({
          email: 'test@example.com',
          name: 'Test User',
          password: 'weak',
        })
        .expect(400);
    });
  });

  describe('/auth/signin (POST)', () => {
    beforeAll(async () => {
      if (!app) {
        throw new Error('App not initialized');
      }
      await request(app.getHttpServer())
        .post('/auth/signup')
        .send({
          email: 'signin@example.com',
          name: 'Signin User',
          password: 'Password123!',
        });
    });

    it('should sign in successfully', () => {
      return request(app.getHttpServer())
        .post('/auth/signin')
        .send({
          email: 'signin@example.com',
          password: 'Password123!',
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('message');
          expect(res.body).toHaveProperty('user');
          expect(res.headers['set-cookie']).toBeDefined();
          const cookies = Array.isArray(res.headers['set-cookie'])
            ? res.headers['set-cookie']
            : [res.headers['set-cookie']];
          expect(cookies.some((cookie: string) => cookie.includes('access_token'))).toBe(true);
          expect(cookies.some((cookie: string) => cookie.includes('refresh_token'))).toBe(true);
        });
    });

    it('should reject invalid credentials', () => {
      return request(app.getHttpServer())
        .post('/auth/signin')
        .send({
          email: 'signin@example.com',
          password: 'WrongPassword123!',
        })
        .expect(401);
    });
  });

  describe('/auth/profile (GET)', () => {
    it('should reject request without token', () => {
      return request(app.getHttpServer())
        .get('/auth/profile')
        .expect(401);
    });
  });

  describe('/auth/refresh (POST)', () => {
    let refreshToken: string;

    beforeAll(async () => {
      if (!app) {
        throw new Error('App not initialized');
      }
      await request(app.getHttpServer())
        .post('/auth/signup')
        .send({
          email: 'refresh@example.com',
          name: 'Refresh User',
          password: 'Password123!',
        })
        .expect((res) => {
          const cookies = Array.isArray(res.headers['set-cookie'])
            ? res.headers['set-cookie']
            : [res.headers['set-cookie']];
          refreshToken = cookies.find((c: string) => c.includes('refresh_token'))!.split(';')[0].split('=')[1];
        });
    });

    it('should refresh tokens successfully', () => {
      return request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`)
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('message');
          expect(res.headers['set-cookie']).toBeDefined();
          const cookies = Array.isArray(res.headers['set-cookie'])
            ? res.headers['set-cookie']
            : [res.headers['set-cookie']];
          expect(cookies.some((cookie: string) => cookie.includes('access_token'))).toBe(true);
          expect(cookies.some((cookie: string) => cookie.includes('refresh_token'))).toBe(true);
        });
    });

    it('should reject invalid refresh token', () => {
      return request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', 'refresh_token=invalid-token')
        .expect(401);
    });
  });
});


# Authentication Backend API

A NestJS-based authentication backend API with MongoDB, JWT authentication, and comprehensive security features.

## Features

- User signup and signin
- JWT-based authentication with access and refresh tokens
- Cookie-based token storage (HttpOnly, Secure, SameSite)
- Refresh token rotation
- Rate limiting with Throttler
- Security middleware (Helmet, CORS)
- Winston logging with daily rotation
- Swagger API documentation
- E2E testing with testcontainers

## Prerequisites

- Node.js 20+
- MongoDB (or Docker for MongoDB)
- npm or yarn

## Installation

```bash
npm install
```

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
PORT=8080
MONGO_URI=mongodb://mongo:27017/authdb
JWT_SECRET=your_jwt_secret_change_in_production
ACCESS_TOKEN_TTL=900
REFRESH_TOKEN_TTL=1209600
COOKIE_DOMAIN=localhost
COOKIE_SECURE=false
COOKIE_SAMESITE=Lax
FRONTEND_ORIGIN=http://localhost:5173
ALLOW_CREDENTIALS=true
THROTTLE_TTL=60
THROTTLE_LIMIT=10
NODE_ENV=development
```

## Running the app

```bash
# Development
npm run start:dev

# Production
npm run build
npm run start:prod
```

## Testing

```bash
# E2E tests
npm run test:e2e
```

## API Documentation

Once running, visit `http://localhost:8080/api` for Swagger documentation.

## Endpoints

- `POST /auth/signup` - Create a new user
- `POST /auth/signin` - Sign in with email and password
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Log out and invalidate tokens
- `GET /auth/profile` - Get authenticated user profile

## Docker

```bash
docker build -t auth-backend .
docker run -p 8080:8080 auth-backend
```

## Security

- Passwords are hashed using bcrypt
- Refresh tokens are hashed and stored in database
- Tokens stored in HttpOnly cookies
- Rate limiting on authentication endpoints
- CORS configured with credentials support
- Helmet for security headers


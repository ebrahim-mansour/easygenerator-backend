import {
  Controller,
  Post,
  Get,
  Body,
  UseGuards,
  Req,
  HttpCode,
  HttpStatus,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request, Response } from 'express';
import { ApiTags, ApiOperation, ApiResponse, ApiCookieAuth, ApiBody } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { SigninDto } from './dto/signin.dto';
import { CurrentUser } from './decorators/current-user.decorator';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../users/users.service';
import { UserDocument } from '../users/schemas/user.schema';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private usersService: UsersService,
    private configService: ConfigService,
  ) {}

  @Post('signup')
  @ApiOperation({ summary: 'Sign up a new user' })
  @ApiResponse({ status: 201, description: 'User successfully created' })
  @ApiResponse({ status: 409, description: 'Email already exists' })
  @ApiResponse({ status: 400, description: 'Validation error' })
  async signup(
    @Body() signupDto: SignupDto,
    @Res() res: Response,
  ): Promise<void> {
    try {
      const user: UserDocument = await this.authService.signup(signupDto);
      const tokens = await this.authService.generateTokens(user._id.toString());

      this.setCookies(res, tokens.accessToken, tokens.refreshToken);

      res.status(HttpStatus.CREATED).json({
        message: 'User created successfully',
        user: {
          id: user._id,
          email: user.email,
          name: user.name,
        },
      });
    } catch (error) {
      if (error.message === 'Email already exists') {
        res.status(HttpStatus.CONFLICT).json({
          statusCode: HttpStatus.CONFLICT,
          message: 'Email already exists',
        });
      } else {
        res.status(HttpStatus.BAD_REQUEST).json({
          statusCode: HttpStatus.BAD_REQUEST,
          message: error.message || 'Signup failed',
        });
      }
    }
  }

  @Post('signin')
  @UseGuards(AuthGuard('local'))
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Sign in a user' })
  @ApiBody({ type: SigninDto })
  @ApiResponse({ status: 200, description: 'User successfully signed in' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  async signin(
    @CurrentUser() user: UserDocument,
    @Res() res: Response,
  ): Promise<void> {
    const tokens = await this.authService.generateTokens(user._id.toString());

    this.setCookies(res, tokens.accessToken, tokens.refreshToken);

    res.json({
      message: 'User signed in successfully',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
      },
    });
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiResponse({ status: 200, description: 'Tokens refreshed successfully' })
  @ApiResponse({ status: 401, description: 'Invalid refresh token' })
  async refresh(@Req() req: Request, @Res() res: Response): Promise<void> {
    const refreshToken = req.cookies?.refresh_token;

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    try {
      const tokens = await this.authService.refreshTokens(refreshToken);
      this.setCookies(res, tokens.accessToken, tokens.refreshToken);

      res.json({
        message: 'Tokens refreshed successfully',
      });
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  @Post('logout')
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Log out a user' })
  @ApiCookieAuth('access_token')
  @ApiResponse({ status: 200, description: 'User successfully logged out' })
  async logout(
    @CurrentUser() user: { userId: string },
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const refreshToken = req.cookies?.refresh_token;

    await this.authService.logout(user.userId, refreshToken);

    this.clearCookies(res);

    res.json({
      message: 'User logged out successfully',
    });
  }

  @Get('profile')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({ summary: 'Get authenticated user profile' })
  @ApiCookieAuth('access_token')
  @ApiResponse({ status: 200, description: 'User profile retrieved successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getProfile(@CurrentUser() user: { userId: string }) {
    const profile = await this.usersService.findById(user.userId);

    if (!profile) {
      throw new UnauthorizedException('User not found');
    }

    return {
      id: profile._id,
      email: profile.email,
      name: profile.name,
      createdAt: profile.createdAt,
    };
  }

  private setCookies(res: Response, accessToken: string, refreshToken: string): void {
    const cookieDomain = this.configService.get<string>('COOKIE_DOMAIN');
    const cookieSecure = this.configService.get<string>('COOKIE_SECURE') === 'true';
    const cookieSameSite = (this.configService.get<string>('COOKIE_SAMESITE') || 'lax').toLowerCase() as 'strict' | 'lax' | 'none';
    const accessTokenTtl = parseInt(this.configService.get<string>('ACCESS_TOKEN_TTL'));
    const refreshTokenTtl = parseInt(this.configService.get<string>('REFRESH_TOKEN_TTL'));
    const isProduction = this.configService.get<string>('NODE_ENV') === 'production';

    // In production when proxying through nginx, don't set domain attribute
    // or set it to undefined/empty to allow cookies to work with proxy
    const cookieOptions: any = {
      httpOnly: true,
      secure: cookieSecure,
      sameSite: cookieSameSite,
      path: '/',
      maxAge: accessTokenTtl * 1000,
    };

    // Only set domain if it's provided and not empty, and not in production
    // When proxying through nginx, cookies should be set without domain restriction
    if (cookieDomain && cookieDomain.trim() !== '' && !isProduction) {
      cookieOptions.domain = cookieDomain;
    }

    res.cookie('access_token', accessToken, cookieOptions);

    res.cookie('refresh_token', refreshToken, {
      ...cookieOptions,
      maxAge: refreshTokenTtl * 1000,
    });
  }

  private clearCookies(res: Response): void {
    const cookieDomain = this.configService.get<string>('COOKIE_DOMAIN');
    const cookieSecure = this.configService.get<string>('COOKIE_SECURE') === 'true';
    const cookieSameSite = (this.configService.get<string>('COOKIE_SAMESITE') || 'lax').toLowerCase() as 'strict' | 'lax' | 'none';
    const isProduction = this.configService.get<string>('NODE_ENV') === 'production';

    const cookieOptions: any = {
      httpOnly: true,
      secure: cookieSecure,
      sameSite: cookieSameSite,
      path: '/',
      maxAge: 0,
    };

    // Only set domain if it's provided and not empty, and not in production
    // When proxying through nginx, cookies should be cleared without domain restriction
    if (cookieDomain && cookieDomain.trim() !== '' && !isProduction) {
      cookieOptions.domain = cookieDomain;
    }

    res.cookie('access_token', '', cookieOptions);
    res.cookie('refresh_token', '', cookieOptions);
  }
}


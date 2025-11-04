import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { User, UserDocument } from '../users/schemas/user.schema';
import { SignupDto } from './dto/signup.dto';
import { WinstonLoggerService } from '../common/logger/winston-logger.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private logger: WinstonLoggerService,
  ) {}

  async signup(signupDto: SignupDto): Promise<UserDocument> {
    const { email, name, password } = signupDto;

    const existingUser = await this.userModel.findOne({ email: email.toLowerCase().trim() });
    if (existingUser) {
      this.logger.warn(`Signup attempt with existing email: ${email}`, 'AuthService');
      throw new Error('Email already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.userModel.create({
      email: email.toLowerCase().trim(),
      name: name.trim(),
      password: hashedPassword,
    });

    this.logger.log(`User signed up: ${user.email}`, 'AuthService');
    return user;
  }

  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.userModel.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      this.logger.warn(`Signin attempt with non-existent email: ${email}`, 'AuthService');
      return null;
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      this.logger.warn(`Signin attempt with invalid password for: ${email}`, 'AuthService');
      return null;
    }

    this.logger.log(`User signed in: ${user.email}`, 'AuthService');
    return user;
  }

  async generateTokens(userId: string): Promise<{ accessToken: string; refreshToken: string }> {
    const accessTokenPayload = { sub: userId };
    const refreshTokenPayload = { sub: userId, jti: this.generateTokenId() };

    const accessToken = this.jwtService.sign(accessTokenPayload, {
      expiresIn: this.configService.get<number>('ACCESS_TOKEN_TTL'),
    });

    const refreshToken = this.jwtService.sign(refreshTokenPayload, {
      expiresIn: this.configService.get<number>('REFRESH_TOKEN_TTL'),
    });

    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    await this.userModel.findByIdAndUpdate(userId, {
      $push: {
        refreshTokens: {
          token: hashedRefreshToken,
          createdAt: new Date(),
        },
      },
    });

    return { accessToken, refreshToken };
  }

  async refreshTokens(
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    let payload: any;
    try {
      payload = this.jwtService.verify(refreshToken);
    } catch (error) {
      throw new Error('Invalid refresh token');
    }

    const userId = payload.sub;
    const user = await this.userModel.findById(userId);
    if (!user || !user.refreshTokens || user.refreshTokens.length === 0) {
      throw new Error('Invalid refresh token');
    }

    let tokenFound = false;
    let tokenIndex = -1;

    for (let i = 0; i < user.refreshTokens.length; i++) {
      const isValid = await bcrypt.compare(refreshToken, user.refreshTokens[i].token);
      if (isValid) {
        tokenFound = true;
        tokenIndex = i;
        break;
      }
    }

    if (!tokenFound) {
      this.logger.warn(`Refresh attempt with invalid token for user: ${userId}`, 'AuthService');
      throw new Error('Invalid refresh token');
    }

    // Remove old refresh token
    user.refreshTokens.splice(tokenIndex, 1);
    await user.save();

    // Generate new tokens
    const newTokens = await this.generateTokens(userId);
    this.logger.log(`Tokens refreshed for user: ${userId}`, 'AuthService');

    return newTokens;
  }

  async logout(userId: string, refreshToken?: string): Promise<void> {
    if (refreshToken) {
      const user = await this.userModel.findById(userId);
      if (user && user.refreshTokens) {
        for (let i = user.refreshTokens.length - 1; i >= 0; i--) {
          const isValid = await bcrypt.compare(refreshToken, user.refreshTokens[i].token);
          if (isValid) {
            user.refreshTokens.splice(i, 1);
          }
        }
        await user.save();
      }
    } else {
      await this.userModel.findByIdAndUpdate(userId, {
        $set: { refreshTokens: [] },
      });
    }

    this.logger.log(`User logged out: ${userId}`, 'AuthService');
  }

  private generateTokenId(): string {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
  }
}


import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signupLocal(dto: AuthDto): Promise<Tokens> {
    const hash = await this.hashData(dto.password); // hash the user's password
    const newUser = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash, // hash field in the DB, which is the hash code of the user's password
      },
    });
    // console.log(this.getTokens(1, dto.email));
    const tokens = await this.getTokens(newUser.id, newUser.email);
    this.updateRtHash(newUser.id, tokens.refresh_token); // add hashRt field in the database
    // (hashRt: hash code of the refresh token)
    return tokens;
    // visit https://jwt.io/ to check the access token
  }

  async signinLocal(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) {
      console.log('not found user');
      throw new ForbiddenException('User not found! Access Denied');
    }
    console.log(dto.password);
    console.log(user.hash);
    console.log(user);
    const passwordMatches = await bcrypt.compare(dto.password, user.hash);
    if (!passwordMatches) {
      throw new ForbiddenException('Wrong password! Access Denied');
    }

    const tokens = await this.getTokens(user.id, user.email);
    this.updateRtHash(user.id, tokens.refresh_token); // add hashRt field in the database
    // when sign in, hashRt will change
    console.log('sign in successful');
    return tokens;
  }

  // simply just delete the hashRt (refresh token) in the DB, so nobody can refresh my credentials and get new access token
  async logout(userId: number) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashRt: {
          not: null,
        },
      },
      data: {
        hashRt: null,
      },
    });
    console.log('logout successful');
  }

  async refreshTokens(userId: number, rt: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user || !user.hashRt)
      throw new ForbiddenException('Not found user RtTokens >> Access denied');
    const rtMatches = await bcrypt.compare(rt, user.hashRt);
    if (!rtMatches)
      throw new ForbiddenException('rt not matches >> Access denied');

    const tokens = await this.getTokens(user.id, user.email);
    this.updateRtHash(user.id, tokens.refresh_token); // add hashRt field in the database
    // when sign in, hashRt will change
    console.log('sign in successful');
    return tokens;
  }

  async updateRtHash(userId: number, rt: string) {
    const hash = await this.hashData(rt);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: { hashRt: hash },
    });
  }
  hashData(password: string) {
    const saltOrRounds = 10;
    return bcrypt.hash(password, saltOrRounds);
  }

  async getTokens(userId: number, email: string) {
    const [at, rt] = await Promise.all([
      // sign the user's id and email to get accessToken and refreshToken
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'at-secret',
          expiresIn: 60 * 15, // accessTokens will expire in 15 minutes
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'rt-secret',
          expiresIn: 7 * 24 * 60 * 60, // refreshTokens will expire in a week
        },
      ),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }
}

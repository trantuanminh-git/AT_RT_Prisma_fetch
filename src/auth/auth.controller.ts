import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import {
  GetCurrentUser,
  GetCurrentUserId,
  Public,
} from 'src/common/decorators';
import { AtGuard, RtGuard } from 'src/common/guards';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
// localhost:3000/auth/local/signin
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED) // 201
  signupLocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signupLocal(dto);
  }

  @Public()
  @Post('local/signin')
  @HttpCode(HttpStatus.OK) // 200
  signinLocal(@Body() dto: AuthDto): Promise<Tokens> {
    console.log('>>>');
    console.log(dto);
    console.log('>>>');
    return this.authService.signinLocal(dto);
  }

  // @UseGuards(AuthGuard('myjwt'))
  @UseGuards(AtGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK) // 200
  logout(@GetCurrentUserId() userId: number) {
    return this.authService.logout(userId);
  }

  // @UseGuards(AuthGuard('myjwt-refresh'))
  @Public()
  @UseGuards(RtGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK) // 200
  refreshTokens(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser('refreshToken') refreshToken: string,
  ) {
    return this.authService.refreshTokens(userId, refreshToken);
  }

  // // @UseGuards(AuthGuard('myjwt'))
  // @UseGuards(AtGuard)
  // @Post('logout')
  // @HttpCode(HttpStatus.OK) // 200
  // logout(@Req() req: Request) {
  //   console.log('>>> Logging out');
  //   const user = req.user; // .user is default field of req: Request ??????
  //   console.log(user);
  //   console.log(user['sub']);
  //   return this.authService.logout(user['sub']);
  // }

  // // @UseGuards(AuthGuard('myjwt-refresh'))
  // @UseGuards(RtGuard)
  // @Post('refresh')
  // @HttpCode(HttpStatus.OK) // 200
  // refreshTokens(@Req() req: Request) {
  //   const user = req.user;
  //   return this.authService.refreshTokens(user['sub'], user['refreshToken']);
  // }
}

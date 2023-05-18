import { Controller, Get, Ip, Req } from '@nestjs/common';
import { Request } from 'express';
import { RealIP } from 'nestjs-real-ip';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @Get('/ip')
  @Get()
  getIpAddressFromRequest(@Req() request: Request): string {
    return request.ip;
  }
  // get(@RealIP() ip: string): string {
  //   console.log(ip);
  //   return ip;
  // }
}

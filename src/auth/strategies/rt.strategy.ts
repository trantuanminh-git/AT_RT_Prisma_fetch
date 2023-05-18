import { Injectable } from '@nestjs/common/decorators';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'myjwt-refresh') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: 'rt-secret',
      passReqToCallback: true, // req will be passed as the first argument to the verify callback.
    });
  }
  async validate(req: Request, payload: any) {
    // return { userId: payload.sub, username: payload.username };
    const refreshToken = req.get('authorization').replace('Bearer', '').trim(); //replace Bearer by null since we don't need 'Bearer'
    return {
      ...payload,
      refreshToken,
    }; //req.user = payload
  }
}

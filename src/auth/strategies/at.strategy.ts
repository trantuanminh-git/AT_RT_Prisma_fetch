import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

type JwtPayload = {
  sub: string;
  email: string;
};

@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'myjwt') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      //   ignoreExpiration: false,
      secretOrKey: 'at-secret',
    });
  }
  // type JwtPayload let we know which fields the payload have
  validate(payload: JwtPayload) {
    // payload will have the field used to sign the token in jwtService.signAsync
    return payload; //req.user = payload

    // return { userId: payload.sub, username: payload.username };
  }
}

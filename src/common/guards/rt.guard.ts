import { AuthGuard } from '@nestjs/passport';

export class RtGuard extends AuthGuard('myjwt-refresh') {
  constructor() {
    super(); // when extends sthg, we will call super()
  }
}

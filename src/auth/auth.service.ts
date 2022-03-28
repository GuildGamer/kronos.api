import { Injectable } from '@nestjs/common';

@Injectable({})
export class AuthService {
  signup() {
    return { msg: 'signup success' };
  }

  signin() {
    return { msg: 'signin success' };
  }
}

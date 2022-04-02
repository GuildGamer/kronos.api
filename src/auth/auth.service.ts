import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signup(dto: AuthDto) {
    //hash the password
    const hash = await argon.hash(dto.password);

    try {
      //save the user to db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      return this.signToken(user.id, user.email);
    } catch (err) {
      if (err instanceof PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
          throw new ForbiddenException('Email already in use');
        }
      }
      throw err;
    }
  }

  async signin(dto: AuthDto) {
    // find the user
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    // throw exception if the user does not exist
    if (!user) throw new ForbiddenException('Credentials are incorrect');

    // compare passwords if the user exists
    const pMatches = await argon.verify(user.hash, dto.password);

    // throw exception if the password is incorrect
    if (!pMatches) throw new ForbiddenException('Credentials are incorrect');

    // return user
    return this.signToken(user.id, user.email);
  }
  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const token = await this.jwtService.signAsync(payload, {
      expiresIn: '30m',
      secret: process.env.JWT_SECRET,
    });

    return {
      access_token: token,
    };
  }
}

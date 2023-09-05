import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argan from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService
  ) {}

  async login(dto: AuthDto) {
    const user = await this.prisma.user.findFirst({
      where: {
        email: dto.email,
      },
    });

    if (!user) throw new ForbiddenException('Credential Incorrect');

    const pwMatch = await argan.verify(user.hash, dto.password);

    if (!pwMatch) throw new ForbiddenException('Credential Incorrect');

    delete user.hash;

    const jwt = await this.signToken(user.id, user.email);

    return {
      access_token : jwt
    };
  }

  async register(dto: AuthDto) {
    //generate password
    const hash = await argan.hash(dto.password);

    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash: hash,
        },
      });

      delete user.hash;

      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credential taken');
        }
      }
    }
  }

  signToken(userId : number, email: string) : Promise<string> {
    return this.jwt.signAsync({
      sub : userId,
      email
    }, {
      expiresIn : '15m',
      secret : this.config.get('JWT_SECRET')
    })
  }
}

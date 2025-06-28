import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDTO, LoginDTO } from './user-dto';
import { IUserResponse } from './user';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from 'src/prisma.service';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class UsersService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async encryptPassword(plainText: string, saltRounds = 10): Promise<string> {
    // const salt = await bcrypt.genSalt(saltRounds);
    // const hash = await bcrypt.hash(plainText, salt);

    // or
    // const hash = await bcrypt.hash(plainText, saltRounds);
    return await bcrypt.hash(plainText, saltRounds);
  }
  async decryptPassword(plainText: string, hash: string): Promise<boolean> {
    return await bcrypt.compare(plainText, hash);
  }

  async signup(payload: CreateUserDTO): Promise<IUserResponse> {
    const existingUser = await this.prisma.user.findFirst({
      where: {
        email: payload.email,
      },
    });
    if (existingUser) {
      // throw new BadRequestException({
      //   message: 'User already exists with this email',
      //   status: 400,
      // });

      // or

      throw new BadRequestException('Signup Error', {
        description: 'User already exists with this email',
        cause: new Error(),
      });
    }
    const hashedPassword = await this.encryptPassword(payload.password);
    payload.password = hashedPassword;
    return await this.prisma.user.create({
      data: payload,
      select: {
        id: true,
        email: true,
      },
    });
  }

  async login(loginDTO: LoginDTO): Promise<{ accessToken: string }> {
    // find user based on email
    const user = await this.prisma.user.findFirst({
      where: {
        email: loginDTO.email,
      },
    });
    if (!user) {
      throw new UnauthorizedException();
    }

    const isMatchedPassword = await this.decryptPassword(
      loginDTO.password,
      user.password || '',
    );
    if (!isMatchedPassword) {
      throw new UnauthorizedException('Invalid password');
    }

    const accessToken = await this.jwtService.signAsync(
      { email: user.email, id: user.id },
      {
        expiresIn: '1d',
      },
    );

    return { accessToken };
  }
}

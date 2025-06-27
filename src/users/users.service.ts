import { BadRequestException, Injectable } from '@nestjs/common';
import { CreateUserDTO } from './create-user-dto';
import { IUserResponse } from './user';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

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
        // firstName: true,
        // lastName: true,
        // createdAt: true,
        // updatedAt: true,
      },
    });
    // save user password in ecrypted format - bycriptjs
    // save the user in the db
    // return id & email
  }

  async encryptPassword(plainText: string, saltRounds = 10): Promise<string> {
    // const salt = await bcrypt.genSalt(saltRounds);
    // const hash = await bcrypt.hash(plainText, salt);

    // or
    const hash = await bcrypt.hash(plainText, saltRounds);
    // return await bcrypt.hash(plainText, salt);

    return hash;
  }
}

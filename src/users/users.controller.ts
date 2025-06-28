import {
  Body,
  Controller,
  Get,
  Post,
  Request,
  UseGuards,
} from '@nestjs/common';
import { CreateUserDTO, LoginDTO } from './user-dto';
import { UsersService } from './users.service';
import { UsersGuard } from './users.guard';

@Controller('users')
export class UsersController {
  constructor(private userService: UsersService) {}
  @Post('/signup')
  async create(
    @Body()
    createUserDTO: CreateUserDTO,
  ) {
    return {
      // message: 'User created successfully',
      // user: createUserDTO,
      response: await this.userService.signup(createUserDTO),
    };
  }

  @Post('/login')
  async login(
    @Body()
    loginDTO: LoginDTO,
  ) {
    return await this.userService.login(loginDTO);
  }

  @UseGuards(UsersGuard)
  @Get('/profile')
  async getProfile(@Request() req: { user: any }) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return await req.user;
  }
}

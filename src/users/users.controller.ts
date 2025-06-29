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
import { AuthGuard } from '../auth/auth.guard';
import { Roles } from 'src/roles/roles.decorator';
import { Role } from 'src/roles/roles.enum';
import { RolesGuard } from 'src/roles/roles.guard';
import { Public } from 'src/public/public.decorator';

@Controller('users')
export class UsersController {
  constructor(private userService: UsersService) {}

  @Public()
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

  @Public()
  @Post('/login')
  async login(
    @Body()
    loginDTO: LoginDTO,
  ) {
    return await this.userService.login(loginDTO);
  }

  @UseGuards(AuthGuard, RolesGuard)
  @Roles(Role.User, Role.Admin, Role.SuperAdmin)
  @Get('/profile')
  async getProfile(@Request() req: { user: any }) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return await req.user;
  }
}

import { Body, Controller, Post } from '@nestjs/common';
import { CreateUserDTO } from './create-user-dto';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private userService: UsersService) {}
  @Post('/signup')
  async create(
    @Body()
    createUserDTO: CreateUserDTO,
  ) {
    // Here you would typically call a service to handle the creation logic
    // For now, we will just return the DTO for demonstration purposes
    return {
      // message: 'User created successfully',
      // user: createUserDTO,
      response: await this.userService.signup(createUserDTO),
    };
  }
}

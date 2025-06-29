import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { PrismaService } from 'src/prisma.service';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from './constants';
import { APP_GUARD } from '@nestjs/core';
import { RolesGuard } from 'src/roles/roles.guard';
import { AuthGuard } from '../auth/auth.guard';

@Module({
  imports: [
    JwtModule.register({
      global: true,
      secret: jwtConstants.secret,
      signOptions: { expiresIn: '60s' },
    }),
  ],
  controllers: [UsersController],
  providers: [
    // with APP_GUARD, it makes the guard applied globally. if want to exclude some of the controller or route, use @Public() decorator. it's setup in roles.guard and auth.guard. and as for how to use it, just add @Public() decorator on the controller or route that you want to exclude from the guard (e.g. login route). perhaps if most of the routes are protected, you can use APP_GUARD to protect all routes and then use @Public() decorator to exclude some of the routes from the guard.
    { provide: APP_GUARD, useClass: AuthGuard },
    { provide: APP_GUARD, useClass: RolesGuard },

    UsersService,
    PrismaService,
  ],
})
export class UsersModule {}

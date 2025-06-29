import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { JwtService } from '@nestjs/jwt';
import { jwtConstants } from '../users/constants';
import { Role } from 'src/roles/roles.enum';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from 'src/public/public.decorator';

// the payload is depends on the login when creating the JWT token
// in this case, we are using id and email as the payload
interface JwtPayload {
  id: string;
  email: string;
  role: Role;
}

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private reflector: Reflector,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }

    const request: Request = context.switchToHttp().getRequest<Request>();
    const token = this.getToken(request);
    if (!token) {
      throw new UnauthorizedException();
    }

    const payload: JwtPayload = await this.jwtService.verifyAsync<JwtPayload>(
      token,
      {
        secret: jwtConstants.secret,
      },
    );

    // data user (yang ada dipayload) dikirim ke users controller (bisa di akses dari req.user atau sejenisny. contoh ada di getProfile)
    request['user'] = payload;
    return true;
  }

  private getToken(request: Request): string | undefined {
    const authHeader = request.headers?.authorization;
    if (typeof authHeader !== 'string') return undefined;
    const [type, token] = authHeader.split(' ');
    return type === 'Bearer' ? token : undefined;
  }
}

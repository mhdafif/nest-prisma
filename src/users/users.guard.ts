import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { JwtService } from '@nestjs/jwt';
import { jwtConstants } from './constants';

// the payload is depends on the login when creating the JWT token
// in this case, we are using id and email as the payload
interface JwtPayload {
  id: string;
  email: string;
}

@Injectable()
export class UsersGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
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

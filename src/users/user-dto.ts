import {
  IsBoolean,
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
} from 'class-validator';

export class CreateUserDTO {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsOptional()
  @IsString()
  firstName?: string;

  @IsOptional()
  @IsString()
  lastName?: string;

  @IsNotEmpty()
  @IsString()
  password: string;

  @IsBoolean()
  @IsOptional()
  blocked: boolean;
}

export class LoginDTO {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsNotEmpty()
  @IsString()
  password: string;
}

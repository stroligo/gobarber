import { getRepository } from 'typeorm';
import { compare } from 'bcryptjs';
import { sign } from 'jsonwebtoken';
import authConfig from '../config/auth';

import AppError from '../errors/AppError';

import User from '../models/User';

interface Request {
  email: string;
  password: string;
}
interface Response {
  user: User;
  token: string;
}

export default class AuthentcateUserService {
  public async execute({ email, password }: Request): Promise<Response> {
    // Validar email
    const usersRepository = getRepository(User);

    const user = await usersRepository.findOne({
      where: { email },
    });

    if (!user) {
      throw new AppError('Incorrect email/password combination', 401);
    }

    // Valida Senha
    // user.password - Senha criptografada
    // password - Senha nao criptografada
    const passwordMatched = await compare(password, user.password);

    if (!passwordMatched) {
      throw new AppError('Incorrect email/password combination', 401);
    }

    const { secret, expiresIn } = authConfig.jwt;
    // JWT TOKE 1) PAYLOAD 2)
    const token = sign({}, secret, {
      subject: user.id,
      expiresIn,
    });

    return { user, token };
  }
}

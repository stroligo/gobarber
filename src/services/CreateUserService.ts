import { getRepository } from 'typeorm';
import { hash } from 'bcryptjs';

import User from '../models/User';

import AppError from '../errors/AppError';

interface Request {
  name: string;
  email: string;
  password: string;
}

export default class CreateUserService {
  public async execute({ name, email, password }: Request): Promise<User> {
    const usersRepository = getRepository(User);

    // Regra - email duplicado
    const checkUserExists = await usersRepository.findOne({
      where: { email },
    });
    if (checkUserExists) {
      throw new AppError('Email adress already used.', 400);
    }
    // Coloca criptografia
    const hashedPassword = await hash(password, 8);

    // Passa para o repositorio
    const user = usersRepository.create({
      name,
      email,
      password: hashedPassword,
    });
    // Salva na base de dados
    await usersRepository.save(user);

    return user;
  }
}

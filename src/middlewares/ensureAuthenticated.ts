import { Request, Response, NextFunction } from 'express';
import { verify } from 'jsonwebtoken';
import authConfig from '../config/auth';

import AppError from '../errors/AppError';

interface TokenPayLoad {
  iat: number;
  exp: number;
  sub: string;
}

export default function ensureAuthenticated(
  request: Request,
  response: Response,
  next: NextFunction
): void {
  // validacao do token JWT

  const authHerader = request.headers.authorization;

  if (!authHerader) {
    throw new AppError('JWT token is missing', 401);
  }
  // Bearer token
  const [, token] = authHerader.split(' ');

  try {
    const decoded = verify(token, authConfig.jwt.secret);

    // Forca uma variavel a um tipo
    const { sub } = decoded as TokenPayLoad;

    // Adiciona user a request em @tupes
    request.user = {
      id: sub,
    };

    return next();
  } catch {
    throw new AppError('Invalid JWT Token', 401);
  }
}

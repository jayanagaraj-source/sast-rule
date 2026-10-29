import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';

export interface AuthedRequest extends Request {
  tenantId: string;
  userId: string;
  role: 'admin' | 'agent' | 'viewer';
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const header = req.header('authorization') ?? '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  try {
    const claims = jwt.verify(token, config.auth.jwtSecret, { issuer: config.auth.jwtIssuer }) as jwt.JwtPayload;
    const authed = req as AuthedRequest;
    authed.tenantId = String(claims.tid);
    authed.userId = String(claims.sub);
    authed.role = claims.role;
    next();
  } catch {
    res.status(401).json({ error: 'unauthorized' });
  }
}

export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  if ((req as AuthedRequest).role !== 'admin') {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  next();
}

export class HttpError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
  }
}

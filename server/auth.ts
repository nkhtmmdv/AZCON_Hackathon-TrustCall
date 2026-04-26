import jwt from 'jsonwebtoken';
import type { Request, Response, NextFunction } from 'express';

export type JwtUser = { userId: string; email: string; role: 'user' | 'admin' | 'superadmin' };

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set. Refusing to start.');
  process.exit(1);
}

export function signToken(payload: JwtUser): string {
  return jwt.sign(payload, JWT_SECRET!, { expiresIn: '7d' });
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET!) as JwtUser;
    (req as any).user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

export function getReqUser(req: Request): JwtUser | null {
  return ((req as any).user as JwtUser) ?? null;
}


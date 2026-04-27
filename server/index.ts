import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import path from 'node:path';
import fs from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';

// ─── util ────────────────────────────────────────────────────────────────────

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function normalizePhoneNumber(input: string): string {
  const digitsOnly = input.replace(/\D/g, '');
  if (digitsOnly.startsWith('994')) return `+${digitsOnly}`;
  if (digitsOnly.length === 9) return `+994${digitsOnly}`;
  if (digitsOnly.length === 10 && digitsOnly.startsWith('0')) return `+994${digitsOnly.substring(1)}`;
  if (digitsOnly.length === 12 && digitsOnly.startsWith('994')) return `+${digitsOnly}`;
  return input.trim();
}

function validateAzerbaijanPhone(number: string): boolean {
  return /^\+994\d{9}$/.test(number);
}

function detectCarrier(phoneNumber: string): string {
  if (!phoneNumber.startsWith('+994')) return 'International';
  const prefix = phoneNumber.substring(4, 6);
  switch (prefix) {
    case '10': case '50': case '51': return 'Azercell';
    case '55': case '99': return 'Bakcell';
    case '70': case '77': return 'Nar';
    default: return 'Unknown Carrier';
  }
}

function mapRiskToStatus(risk: number): 'safe' | 'suspicious' | 'spam' | 'scam' {
  if (risk >= 85) return 'scam';
  if (risk >= 60) return 'spam';
  if (risk >= 30) return 'suspicious';
  return 'safe';
}

function uuid(): string {
  return randomUUID();
}

// ─── auth ────────────────────────────────────────────────────────────────────

type JwtUser = { userId: string; email: string; role: 'user' | 'admin' | 'superadmin' };

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-in-production';

function signToken(payload: JwtUser): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function requireAuth(req: Request, res: Response, next: NextFunction) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JwtUser;
    (req as any).user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

function getReqUser(req: Request): JwtUser | null {
  return ((req as any).user as JwtUser) ?? null;
}

// ─── db ──────────────────────────────────────────────────────────────────────

type DbUserRole = 'user' | 'admin' | 'superadmin';
type DbUser = {
  id: string; name: string; email: string; passwordHash: string;
  role: DbUserRole; createdAt: string;
};
type NumberStatus = 'safe' | 'suspicious' | 'spam' | 'scam';
type DbNumber = {
  id: string; phoneNumber: string; status: NumberStatus; riskScore: number;
  carrier: string; source: 'System' | 'User Discovery'; totalLookups: number;
  reportCount: number; reportRiskPercentage: number; scamReportPercentage: number;
  blockedCount: number; lastCheckedAt: string | null; lastUpdated: string; createdAt: string;
};
type ReportCategory = 'app_fraud' | 'vishing' | 'caller_id_spoofing' | 'spam' | 'other';
type DbReport = {
  id: string; numberId: string; reporterUserId: string;
  category: ReportCategory; description: string | null; createdAt: string;
};
type DbActivity = {
  id: string; userId: string; action: 'lookup' | 'report' | 'block';
  details: string; dangerLevel: number; createdAt: string;
};
type JsonDb = {
  users: DbUser[]; numbers: DbNumber[]; reports: DbReport[];
  activity: DbActivity[]; userBlocks: { id: string; userId: string; numberId: string; createdAt: string }[];
};

const DATA_DIR = path.resolve(process.cwd(), 'server', 'data');
const DB_PATH = path.join(DATA_DIR, 'db.json');
let writeLock: Promise<void> = Promise.resolve();

async function ensureDataDir() {
  try { await fs.mkdir(DATA_DIR, { recursive: true }); } catch {}
}

async function readDb(): Promise<JsonDb> {
  await ensureDataDir();
  try {
    const raw = await fs.readFile(DB_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    return {
      users: Array.isArray(parsed?.users) ? parsed.users : [],
      numbers: Array.isArray(parsed?.numbers) ? parsed.numbers : [],
      reports: Array.isArray(parsed?.reports) ? parsed.reports : [],
      activity: Array.isArray(parsed?.activity) ? parsed.activity : [],
      userBlocks: Array.isArray(parsed?.userBlocks) ? parsed.userBlocks : [],
    };
  } catch {
    return { users: [], numbers: [], reports: [], activity: [], userBlocks: [] };
  }
}

async function writeDb(next: JsonDb): Promise<void> {
  await ensureDataDir();
  writeLock = writeLock.then(async () => {
    const tmp = `${DB_PATH}.${Date.now()}.tmp`;
    const json = JSON.stringify(next, null, 2);
    await fs.writeFile(tmp, json, 'utf8');
    await fs.rename(tmp, DB_PATH);
  });
  return writeLock;
}

async function safeWriteDb(db: JsonDb): Promise<void> {
  try { await writeDb(db); } catch {}
}

// ─── app ─────────────────────────────────────────────────────────────────────

const app = express();

app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '100kb' }));

const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
function rateLimit(windowMs: number, maxRequests: number) {
  return (req: Request, res: Response, next: NextFunction) => {
    const key = req.ip || 'unknown';
    const now = Date.now();
    const entry = rateLimitMap.get(key);
    if (!entry || now > entry.resetAt) {
      rateLimitMap.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    if (entry.count >= maxRequests) {
      return res.status(429).json({ error: 'Too many requests, please try again later.' });
    }
    entry.count += 1;
    next();
  };
}

const PORT = Number(process.env.API_PORT || 5175);

function getScamReportPercentage(db: JsonDb, numberId: string): number {
  const related = db.reports.filter((r) => r.numberId === numberId);
  if (related.length === 0) return 0;
  const scam = related.filter((r) => r.category === 'app_fraud' || r.category === 'vishing').length;
  return (scam / related.length) * 100;
}

function getReportPercentageFromLookups(reportCount: number, _totalLookups: number): number {
  return Math.min(100, Math.max(0, Number(reportCount || 0)) * 10);
}

// Demo users — work without any db file
const DEMO_USERS = [
  { id: 'demo-user-001', name: 'Demo User', email: 'user@example.com', password: 'password', role: 'user' as const },
  { id: 'demo-admin-001', name: 'Demo Admin', email: 'admin@example.com', password: 'password', role: 'superadmin' as const },
];

// ─── Routes ──────────────────────────────────────────────────────────────────

app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

app.post('/api/auth/register', rateLimit(15 * 60 * 1000, 10), async (req, res) => {
  const body = z.object({
    name: z.string().min(1),
    email: z.string().email(),
    password: z.string().min(6),
  }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: 'Invalid input' });

  const name = body.data.name.trim();
  const email = normalizeEmail(body.data.email);

  if (DEMO_USERS.some(u => u.email === email)) {
    return res.status(409).json({ error: 'Email already exists' });
  }

  const password_hash = await bcrypt.hash(body.data.password, 10);
  try {
    const id = uuid();
    const db = await readDb();
    if (db.users.some((u) => normalizeEmail(u.email) === email)) {
      return res.status(409).json({ error: 'Email already exists' });
    }
    db.users.unshift({ id, name, email, passwordHash: password_hash, role: 'user', createdAt: new Date().toISOString() });
    await safeWriteDb(db);
    const token = signToken({ userId: id, email, role: 'user' });
    res.json({ token, user: { id, name, email, role: 'user' } });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', rateLimit(15 * 60 * 1000, 20), async (req, res) => {
  const body = z.object({
    email: z.string().email(),
    password: z.string().min(1),
  }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: 'Invalid input' });

  const email = normalizeEmail(body.data.email);

  const demoUser = DEMO_USERS.find(u => u.email === email);
  if (demoUser && body.data.password === demoUser.password) {
    const token = signToken({ userId: demoUser.id, email: demoUser.email, role: demoUser.role });
    return res.json({ token, user: { id: demoUser.id, name: demoUser.name, email: demoUser.email, role: demoUser.role } });
  }

  try {
    const db = await readDb();
    const user = db.users.find((u) => normalizeEmail(u.email) === email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(body.data.password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = signToken({ userId: user.id, email: user.email, role: user.role });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.get('/api/activity', requireAuth, async (req, res) => {
  const u = getReqUser(req)!;
  try {
    const db = await readDb();
    const items = db.activity
      .filter((a) => a.userId === u.userId)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
      .slice(0, 50)
      .map((a) => ({ id: a.id, action: a.action, details: a.details, dangerLevel: a.dangerLevel, createdAt: a.createdAt }));
    res.json({ items });
  } catch {
    res.json({ items: [] });
  }
});

app.get('/api/numbers/lookup', requireAuth, async (req, res) => {
  const u = getReqUser(req)!;
  const raw = String(req.query.number || '');
  const number = normalizePhoneNumber(raw);
  if (!validateAzerbaijanPhone(number)) return res.status(400).json({ error: 'Malformed number' });

  try {
    const db = await readDb();
    let record = db.numbers.find((n) => n.phoneNumber === number) || null;
    const nowIso = new Date().toISOString();

    if (!record) {
      const newRec: DbNumber = {
        id: uuid(), phoneNumber: number, status: 'safe', riskScore: 0,
        carrier: detectCarrier(number), source: 'User Discovery', totalLookups: 1,
        reportCount: 0, reportRiskPercentage: 0, scamReportPercentage: 0,
        blockedCount: 0, lastCheckedAt: nowIso, lastUpdated: nowIso, createdAt: nowIso,
      };
      db.numbers.unshift(newRec);
      record = newRec;
    } else {
      record.totalLookups = Number(record.totalLookups || 0) + 1;
      record.reportRiskPercentage = getReportPercentageFromLookups(Number(record.reportCount || 0), Number(record.totalLookups || 0));
      record.lastCheckedAt = nowIso;
      record.lastUpdated = nowIso;
    }

    db.activity.unshift({ id: uuid(), userId: u.userId, action: 'lookup', details: `Checked ${number}`, dangerLevel: Number(record.riskScore || 0), createdAt: nowIso });
    await safeWriteDb(db);

    res.json({ number: { id: record.id, number: record.phoneNumber, status: record.status, riskScore: record.riskScore, carrier: record.carrier, source: record.source, totalLookups: Number(record.totalLookups || 0), reportCount: record.reportCount, reportRiskPercentage: Number(record.reportRiskPercentage || 0), scamReportPercentage: Number(record.scamReportPercentage || 0), blockedCount: Number(record.blockedCount || 0) } });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/numbers/report', requireAuth, async (req, res) => {
  const u = getReqUser(req)!;
  const body = z.object({
    number: z.string().min(1),
    category: z.enum(['app_fraud', 'vishing', 'caller_id_spoofing', 'spam', 'other']),
    description: z.string().max(500).optional(),
  }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: 'Invalid input' });

  const number = normalizePhoneNumber(body.data.number);
  if (!validateAzerbaijanPhone(number)) return res.status(400).json({ error: 'Malformed number' });

  try {
    const db = await readDb();
    let existing = db.numbers.find((n) => n.phoneNumber === number);
    const nowIso = new Date().toISOString();
    if (!existing) {
      const created: DbNumber = { id: uuid(), phoneNumber: number, status: 'safe', riskScore: 0, carrier: detectCarrier(number), source: 'User Discovery', totalLookups: 0, reportCount: 0, reportRiskPercentage: 0, scamReportPercentage: 0, blockedCount: 0, lastCheckedAt: null, lastUpdated: nowIso, createdAt: nowIso };
      db.numbers.unshift(created);
      existing = created;
    }
    const nextRisk = Math.min(99, Number(existing.riskScore || 0) + 10);
    const cat = body.data.category as ReportCategory;
    db.reports.unshift({ id: uuid(), numberId: existing.id, reporterUserId: u.userId, category: cat, description: body.data.description?.trim() || null, createdAt: nowIso });
    existing.riskScore = nextRisk;
    existing.status = mapRiskToStatus(nextRisk);
    existing.reportCount = Number(existing.reportCount || 0) + 1;
    existing.totalLookups = Math.max(Number(existing.totalLookups || 0), Number(existing.reportCount || 0));
    existing.reportRiskPercentage = getReportPercentageFromLookups(Number(existing.reportCount || 0), Number(existing.totalLookups || 0));
    existing.scamReportPercentage = getScamReportPercentage(db, existing.id);
    existing.blockedCount = Number(existing.blockedCount || 0);
    existing.lastUpdated = nowIso;
    db.activity.unshift({ id: uuid(), userId: u.userId, action: 'report', details: `Reported ${number} (${cat.replaceAll('_', ' ')})`, dangerLevel: nextRisk, createdAt: nowIso });
    await safeWriteDb(db);
    res.json({ number: { id: existing.id, number: existing.phoneNumber, status: existing.status, riskScore: existing.riskScore, carrier: existing.carrier, source: existing.source, totalLookups: Number(existing.totalLookups || 0), reportCount: existing.reportCount, reportRiskPercentage: Number(existing.reportRiskPercentage || 0), scamReportPercentage: Number(existing.scamReportPercentage || 0), blockedCount: Number(existing.blockedCount || 0) } });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/numbers/block', requireAuth, async (req, res) => {
  const u = getReqUser(req)!;
  const body = z.object({ number: z.string().min(1) }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: 'Invalid input' });

  const number = normalizePhoneNumber(body.data.number);
  if (!validateAzerbaijanPhone(number)) return res.status(400).json({ error: 'Malformed number' });

  try {
    const db = await readDb();
    let existing = db.numbers.find((n) => n.phoneNumber === number);
    const nowIso = new Date().toISOString();
    if (!existing) {
      const newRec: DbNumber = { id: uuid(), phoneNumber: number, status: 'safe', riskScore: 0, carrier: detectCarrier(number), source: 'User Discovery', totalLookups: 0, reportCount: 0, reportRiskPercentage: 0, scamReportPercentage: 0, blockedCount: 0, lastCheckedAt: nowIso, lastUpdated: nowIso, createdAt: nowIso };
      db.numbers.unshift(newRec);
      existing = newRec;
    } else {
      existing.blockedCount = Number(existing.blockedCount || 0);
      existing.lastUpdated = nowIso;
    }
    const alreadyBlocked = db.userBlocks.some((b) => b.userId === u.userId && b.numberId === existing!.id);
    if (!alreadyBlocked) {
      db.userBlocks.unshift({ id: uuid(), userId: u.userId, numberId: existing.id, createdAt: nowIso });
    }
    db.activity.unshift({ id: uuid(), userId: u.userId, action: 'block', details: `Blocked ${number}`, dangerLevel: Number(existing.riskScore || 0), createdAt: nowIso });
    await safeWriteDb(db);
    res.json({ number: { id: existing.id, number: existing.phoneNumber, status: existing.status, riskScore: existing.riskScore, carrier: existing.carrier, source: existing.source, totalLookups: Number(existing.totalLookups || 0), reportCount: existing.reportCount, reportRiskPercentage: Number(existing.reportRiskPercentage || 0), scamReportPercentage: Number(existing.scamReportPercentage || 0), blockedCount: Number(existing.blockedCount || 0) } });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/numbers', requireAuth, async (req, res) => {
  const u = getReqUser(req)!;
  if (u.role !== 'admin' && u.role !== 'superadmin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const db = await readDb();
    const items = [...db.numbers]
      .sort((a, b) => new Date(b.lastUpdated).getTime() - new Date(a.lastUpdated).getTime())
      .slice(0, 500)
      .map((n) => ({ number: n.phoneNumber, status: n.status, riskScore: n.riskScore, carrier: n.carrier, source: n.source, reportCount: n.reportCount, totalLookups: Number(n.totalLookups || 0), reportRiskPercentage: Number(n.reportRiskPercentage || getReportPercentageFromLookups(Number(n.reportCount || 0), Number(n.totalLookups || 0))), scamReportPercentage: Number(n.scamReportPercentage || getScamReportPercentage(db, n.id)), blockedCount: Number(n.blockedCount || 0), lastUpdated: n.lastUpdated }));
    res.json({ items });
  } catch {
    res.json({ items: [] });
  }
});

app.post('/api/sync/numbers', requireAuth, async (req, res) => {
  const u = getReqUser(req)!;
  if (u.role !== 'admin' && u.role !== 'superadmin') return res.status(403).json({ error: 'Forbidden' });
  const body = z.object({
    items: z.array(z.object({
      number: z.string().min(1),
      status: z.enum(['safe', 'suspicious', 'spam', 'scam']),
      riskScore: z.number(),
      carrier: z.string().optional(),
      source: z.enum(['System', 'User Discovery']).optional(),
      reportCount: z.number().int().min(0),
      totalLookups: z.number().int().min(0).optional(),
      lastUpdated: z.string().optional(),
    })),
  }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: 'Invalid input' });

  try {
    const db = await readDb();
    const nowIso = new Date().toISOString();
    let upserted = 0;
    for (const item of body.data.items) {
      const normalized = normalizePhoneNumber(item.number);
      if (!validateAzerbaijanPhone(normalized)) continue;
      let existing = db.numbers.find((n) => n.phoneNumber === normalized);
      const nextRisk = Math.max(0, Math.min(99, Math.round(Number(item.riskScore || 0))));
      const nextReportCount = Math.max(0, Math.round(Number(item.reportCount || 0)));
      const nextTotalLookups = Math.max(Math.max(0, Math.round(Number(item.totalLookups || 0))), nextReportCount);
      const nextLastUpdated = item.lastUpdated || nowIso;
      if (!existing) {
        existing = { id: uuid(), phoneNumber: normalized, status: mapRiskToStatus(nextRisk), riskScore: nextRisk, carrier: item.carrier || detectCarrier(normalized), source: item.source || 'User Discovery', totalLookups: nextTotalLookups, reportCount: nextReportCount, reportRiskPercentage: getReportPercentageFromLookups(nextReportCount, nextTotalLookups), scamReportPercentage: 0, blockedCount: 0, lastCheckedAt: null, lastUpdated: nextLastUpdated, createdAt: nowIso };
        db.numbers.unshift(existing);
      } else {
        existing.riskScore = nextRisk;
        existing.status = mapRiskToStatus(nextRisk);
        existing.carrier = item.carrier || existing.carrier;
        existing.source = item.source || existing.source;
        existing.reportCount = nextReportCount;
        existing.totalLookups = nextTotalLookups;
        existing.reportRiskPercentage = getReportPercentageFromLookups(existing.reportCount, existing.totalLookups);
        existing.scamReportPercentage = getScamReportPercentage(db, existing.id);
        existing.lastUpdated = nextLastUpdated;
      }
      upserted += 1;
    }
    await safeWriteDb(db);
    res.json({ ok: true, upserted });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Start ───────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
});

export default app;

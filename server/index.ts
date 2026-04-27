import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { readDb, writeDb, type DbNumber, type JsonDb, type ReportCategory } from './db';
import { getReqUser, requireAuth, signToken } from './auth';
import { detectCarrier, mapRiskToStatus, normalizeEmail, normalizePhoneNumber, uuid, validateAzerbaijanPhone } from './util';

const app = express();

// Security headers
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});

// CORS: allow any origin (needed for Vercel deployments)
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '100kb' }));

// Simple in-memory rate limiter
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
function rateLimit(windowMs: number, maxRequests: number) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
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

function getReportRiskPercentage(reportCount: number): number {
  return Math.min(100, Math.max(0, Number(reportCount || 0) * 10));
}

function getScamReportPercentage(db: JsonDb, numberId: string): number {
  const relatedReports = db.reports.filter((r) => r.numberId === numberId);
  if (relatedReports.length === 0) return 0;
  const scamLikeCount = relatedReports.filter((r) => r.category === 'app_fraud' || r.category === 'vishing').length;
  return (scamLikeCount / relatedReports.length) * 100;
}

function getReportPercentageFromLookups(reportCount: number, totalLookups: number): number {
  const safeReports = Math.max(0, Number(reportCount || 0));
  return Math.min(100, safeReports * 10);
}

// Helper to safely write db (Vercel has read-only fs, so we silently ignore write errors)
async function safeWriteDb(db: JsonDb): Promise<void> {
  try {
    await writeDb(db);
  } catch {
    // Silently ignore on read-only filesystems (e.g. Vercel)
  }
}

async function ensureSchemaAndSeed() {
  const superEmail = process.env.SUPERADMIN_EMAIL ? normalizeEmail(process.env.SUPERADMIN_EMAIL) : null;
  const superPass = process.env.SUPERADMIN_PASSWORD || null;

  if (!superEmail || !superPass) {
    console.warn('WARNING: SUPERADMIN_EMAIL and SUPERADMIN_PASSWORD are not set. Skipping admin seed.');
    return;
  }

  try {
    const db = await readDb();
    const existing = db.users.find((u) => normalizeEmail(u.email) === superEmail);
    if (!existing) {
      const password_hash = await bcrypt.hash(superPass, 10);
      db.users.unshift({
        id: uuid(),
        name: 'Super Admin',
        email: superEmail,
        passwordHash: password_hash,
        role: 'superadmin',
        createdAt: new Date().toISOString(),
      });
      await safeWriteDb(db);
    }
  } catch {
    // Ignore seed errors on read-only filesystems
  }
}

app.get('/api/health', async (_req, res) => {
  res.json({ ok: true });
});

app.post('/api/auth/register', rateLimit(15 * 60 * 1000, 10), async (req, res) => {
  const body = z
    .object({
      name: z.string().min(1),
      email: z.string().email(),
      password: z.string().min(6),
    })
    .safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: 'Invalid input' });

  const name = body.data.name.trim();
  const email = normalizeEmail(body.data.email);
  const password_hash = await bcrypt.hash(body.data.password, 10);

  try {
    const id = uuid();
    const db = await readDb();
    if (db.users.some((u) => normalizeEmail(u.email) === email)) {
      return res.status(409).json({ error: 'Email already exists' });
    }
    db.users.unshift({
      id,
      name,
      email,
      passwordHash: password_hash,
      role: 'user',
      createdAt: new Date().toISOString(),
    });
    await safeWriteDb(db);
    const token = signToken({ userId: id, email, role: 'user' });
    res.json({ token, user: { id, name, email, role: 'user' } });
  } catch (e: any) {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', rateLimit(15 * 60 * 1000, 20), async (req, res) => {
  const body = z
    .object({
      email: z.string().email(),
      password: z.string().min(1),
    })
    .safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: 'Invalid input' });

  const email = normalizeEmail(body.data.email);

  // Demo users fallback (works even if db.json is read-only)
  const DEMO_USERS = [
    { id: 'demo-user-001', name: 'Demo User', email: 'user@example.com', password: 'password', role: 'user' as const },
    { id: 'demo-admin-001', name: 'Demo Admin', email: 'admin@example.com', password: 'password', role: 'superadmin' as const },
  ];
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
        id: uuid(),
        phoneNumber: number,
        status: 'safe',
        riskScore: 0,
        carrier: detectCarrier(number),
        source: 'User Discovery',
        totalLookups: 1,
        reportCount: 0,
        reportRiskPercentage: 0,
        scamReportPercentage: 0,
        blockedCount: 0,
        lastCheckedAt: nowIso,
        lastUpdated: nowIso,
        createdAt: nowIso,
      };
      db.numbers.unshift(newRec);
      record = newRec;
    } else {
      record.totalLookups = Number(record.totalLookups || 0) + 1;
      record.reportRiskPercentage = getReportPercentageFromLookups(
        Number(record.reportCount || 0),
        Number(record.totalLookups || 0)
      );
      record.lastCheckedAt = nowIso;
      record.lastUpdated = nowIso;
    }

    db.activity.unshift({
      id: uuid(),
      userId: u.userId,
      action: 'lookup',
      details: `Checked ${number}`,
      dangerLevel: Number(record.riskScore || 0),
      createdAt: nowIso,
    });
    await safeWriteDb(db);

    res.json({
      number: {
        id: record.id,
        number: record.phoneNumber,
        status: record.status,
        riskScore: record.riskScore,
        carrier: record.carrier,
        source: record.source,
        totalLookups: Number(record.totalLookups || 0),
        reportCount: record.reportCount,
        reportRiskPercentage: Number(record.reportRiskPercentage || 0),
        scamReportPercentage: Number(record.scamReportPercentage || 0),
        blockedCount: Number(record.blockedCount || 0),
      },
    });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/numbers/report', requireAuth, async (req, res) => {
  const u = getReqUser(req)!;
  const body = z
    .object({
      number: z.string().min(1),
      category: z.enum(['app_fraud', 'vishing', 'caller_id_spoofing', 'spam', 'other']),
      description: z.string().max(500).optional(),
    })
    .safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: 'Invalid input' });

  const number = normalizePhoneNumber(body.data.number);
  if (!validateAzerbaijanPhone(number)) return res.status(400).json({ error: 'Malformed number' });

  try {
    const db = await readDb();
    let existing = db.numbers.find((n) => n.phoneNumber === number);
    const nowIso = new Date().toISOString();
    if (!existing) {
      const created: DbNumber = {
        id: uuid(),
        phoneNumber: number,
        status: 'safe',
        riskScore: 0,
        carrier: detectCarrier(number),
        source: 'User Discovery',
        totalLookups: 0,
        reportCount: 0,
        reportRiskPercentage: 0,
        scamReportPercentage: 0,
        blockedCount: 0,
        lastCheckedAt: null,
        lastUpdated: nowIso,
        createdAt: nowIso,
      };
      db.numbers.unshift(created);
      existing = created;
    }
    const nextRisk = Math.min(99, Number(existing.riskScore || 0) + 10);
    const nextStatus = mapRiskToStatus(nextRisk);

    const cat = body.data.category as ReportCategory;
    db.reports.unshift({
      id: uuid(),
      numberId: existing.id,
      reporterUserId: u.userId,
      category: cat,
      description: body.data.description?.trim() || null,
      createdAt: nowIso,
    });

    existing.riskScore = nextRisk;
    existing.status = nextStatus;
    existing.reportCount = Number(existing.reportCount || 0) + 1;
    existing.totalLookups = Math.max(Number(existing.totalLookups || 0), Number(existing.reportCount || 0));
    existing.reportRiskPercentage = getReportPercentageFromLookups(
      Number(existing.reportCount || 0),
      Number(existing.totalLookups || 0)
    );
    existing.scamReportPercentage = getScamReportPercentage(db, existing.id);
    existing.blockedCount = Number(existing.blockedCount || 0);
    existing.lastUpdated = nowIso;

    db.activity.unshift({
      id: uuid(),
      userId: u.userId,
      action: 'report',
      details: `Reported ${number} (${cat.replaceAll('_', ' ')}) — ${body.data.description?.trim() || ''}`.trim(),
      dangerLevel: nextRisk,
      createdAt: nowIso,
    });

    await safeWriteDb(db);

    res.json({
      number: {
        id: existing.id,
        number: existing.phoneNumber,
        status: existing.status,
        riskScore: existing.riskScore,
        carrier: existing.carrier,
        source: existing.source,
        totalLookups: Number(existing.totalLookups || 0),
        reportCount: existing.reportCount,
        reportRiskPercentage: Number(existing.reportRiskPercentage || 0),
        scamReportPercentage: Number(existing.scamReportPercentage || 0),
        blockedCount: Number(existing.blockedCount || 0),
      },
    });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/numbers/block', requireAuth, async (req, res) => {
  const u = getReqUser(req)!;
  const body = z
    .object({
      number: z.string().min(1),
    })
    .safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: 'Invalid input' });

  const number = normalizePhoneNumber(body.data.number);
  if (!validateAzerbaijanPhone(number)) return res.status(400).json({ error: 'Malformed number' });

  try {
    const db = await readDb();
    let existing = db.numbers.find((n) => n.phoneNumber === number);
    const nowIso = new Date().toISOString();

    if (!existing) {
      const newRec: DbNumber = {
        id: uuid(),
        phoneNumber: number,
        status: 'safe',
        riskScore: 0,
        carrier: detectCarrier(number),
        source: 'User Discovery',
        totalLookups: 0,
        reportCount: 0,
        reportRiskPercentage: 0,
        scamReportPercentage: 0,
        blockedCount: 0,
        lastCheckedAt: nowIso,
        lastUpdated: nowIso,
        createdAt: nowIso,
      };
      db.numbers.unshift(newRec);
      existing = newRec;
    } else {
      existing.blockedCount = Number(existing.blockedCount || 0);
      existing.reportRiskPercentage = Number(existing.reportRiskPercentage || getReportPercentageFromLookups(Number(existing.reportCount || 0), Number(existing.totalLookups || 0)));
      existing.scamReportPercentage = Number(existing.scamReportPercentage || getScamReportPercentage(db, existing.id));
      existing.lastUpdated = nowIso;
    }

    const alreadyBlocked = db.userBlocks.some((b) => b.userId === u.userId && b.numberId === existing!.id);
    if (!alreadyBlocked) {
      db.userBlocks.unshift({
        id: uuid(),
        userId: u.userId,
        numberId: existing.id,
        createdAt: nowIso,
      });
    }

    db.activity.unshift({
      id: uuid(),
      userId: u.userId,
      action: 'block',
      details: `Blocked ${number}`,
      dangerLevel: Number(existing.riskScore || 0),
      createdAt: nowIso,
    });

    await safeWriteDb(db);
    res.json({
      number: {
        id: existing.id,
        number: existing.phoneNumber,
        status: existing.status,
        riskScore: existing.riskScore,
        carrier: existing.carrier,
        source: existing.source,
        totalLookups: Number(existing.totalLookups || 0),
        reportCount: existing.reportCount,
        reportRiskPercentage: Number(existing.reportRiskPercentage || 0),
        scamReportPercentage: Number(existing.scamReportPercentage || 0),
        blockedCount: Number(existing.blockedCount || 0),
      },
    });
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
      .map((n) => ({
        number: n.phoneNumber,
        status: n.status,
        riskScore: n.riskScore,
        carrier: n.carrier,
        source: n.source,
        reportCount: n.reportCount,
        totalLookups: Number(n.totalLookups || 0),
        reportRiskPercentage: Number(n.reportRiskPercentage || getReportPercentageFromLookups(Number(n.reportCount || 0), Number(n.totalLookups || 0))),
        scamReportPercentage: Number(n.scamReportPercentage || getScamReportPercentage(db, n.id)),
        blockedCount: Number(n.blockedCount || 0),
        lastUpdated: n.lastUpdated,
      }));
    res.json({ items });
  } catch {
    res.json({ items: [] });
  }
});

app.post('/api/sync/numbers', requireAuth, async (req, res) => {
  const u = getReqUser(req)!;
  if (u.role !== 'admin' && u.role !== 'superadmin') return res.status(403).json({ error: 'Forbidden' });
  const body = z
    .object({
      items: z.array(
        z.object({
          number: z.string().min(1),
          status: z.enum(['safe', 'suspicious', 'spam', 'scam']),
          riskScore: z.number(),
          carrier: z.string().optional(),
          source: z.enum(['System', 'User Discovery']).optional(),
          reportCount: z.number().int().min(0),
          totalLookups: z.number().int().min(0).optional(),
          lastUpdated: z.string().optional(),
        })
      ),
    })
    .safeParse(req.body);
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
        existing = {
          id: uuid(),
          phoneNumber: normalized,
          status: mapRiskToStatus(nextRisk),
          riskScore: nextRisk,
          carrier: item.carrier || detectCarrier(normalized),
          source: item.source || 'User Discovery',
          totalLookups: nextTotalLookups,
          reportCount: nextReportCount,
          reportRiskPercentage: getReportPercentageFromLookups(nextReportCount, nextTotalLookups),
          scamReportPercentage: 0,
          blockedCount: 0,
          lastCheckedAt: null,
          lastUpdated: nextLastUpdated,
          createdAt: nowIso,
        };
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

ensureSchemaAndSeed()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`API listening on http://localhost:${PORT}`);
    });
  })
  .catch((e) => {
    console.error('Failed to start API:', e);
    process.exit(1);
  });

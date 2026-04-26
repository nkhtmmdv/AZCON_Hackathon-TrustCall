import path from 'node:path';
import fs from 'node:fs/promises';

export type DbUserRole = 'user' | 'admin' | 'superadmin';
export type DbUser = {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  role: DbUserRole;
  createdAt: string;
};

export type NumberStatus = 'safe' | 'suspicious' | 'spam' | 'scam';
export type DbNumber = {
  id: string;
  phoneNumber: string;
  status: NumberStatus;
  riskScore: number;
  carrier: string;
  source: 'System' | 'User Discovery';
  totalLookups: number;
  reportCount: number;
  reportRiskPercentage: number;
  scamReportPercentage: number;
  blockedCount: number;
  lastCheckedAt: string | null;
  lastUpdated: string;
  createdAt: string;
};

export type ReportCategory = 'app_fraud' | 'vishing' | 'caller_id_spoofing' | 'spam' | 'other';
export type DbReport = {
  id: string;
  numberId: string;
  reporterUserId: string;
  category: ReportCategory;
  description: string | null;
  createdAt: string;
};

export type DbActivity = {
  id: string;
  userId: string;
  action: 'lookup' | 'report' | 'block';
  details: string;
  dangerLevel: number;
  createdAt: string;
};

export type JsonDb = {
  users: DbUser[];
  numbers: DbNumber[];
  reports: DbReport[];
  activity: DbActivity[];
  userBlocks: { id: string; userId: string; numberId: string; createdAt: string }[];
};

const DATA_DIR = path.resolve(process.cwd(), 'server', 'data');
const DB_PATH = path.join(DATA_DIR, 'db.json');

let writeLock: Promise<void> = Promise.resolve();

async function ensureDataDir() {
  await fs.mkdir(DATA_DIR, { recursive: true });
}

export async function readDb(): Promise<JsonDb> {
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

export async function writeDb(next: JsonDb): Promise<void> {
  await ensureDataDir();
  // Serialize writes to avoid corruption
  writeLock = writeLock.then(async () => {
    const tmp = `${DB_PATH}.${Date.now()}.tmp`;
    const json = JSON.stringify(next, null, 2);
    await fs.writeFile(tmp, json, 'utf8');
    await fs.rename(tmp, DB_PATH);
  });
  return writeLock;
}



/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  Phone, 
  PhoneIncoming, 
  PhoneOff, 
  Activity, 
  Map as MapIcon, 
  BarChart3, 
  Settings, 
  Lock, 
  Zap, 
  ChevronRight,
  Database,
  Radio,
  Clock,
  CheckCircle2,
  Eye
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  LineChart, 
  Line,
  AreaChart,
  Area
} from 'recharts';
import { SIMULATED_CALLS, getRiskLevel } from './services/telecomService';
import { CallEvent, CallRiskLevel } from './types/telecom';

// Simulation scenarios for dynamic demo
const SCAM_SCENARIOS = [
  { 
    number: '+994501234567', 
    name: 'Bank Impersonation', 
    risk: 92, 
    metadata: 'Fake Kapital Bank Support',
    description: 'Spoofing bank customer service to steal credentials'
  },
  { 
    number: '+994511234568', 
    name: 'Neighbor Spoofing', 
    risk: 89, 
    metadata: 'Local Area Code Spoofing',
    description: 'Using nearby numbers to appear trustworthy'
  },
  { 
    number: '+994101234569', 
    name: 'Fake Gov Support', 
    risk: 95, 
    metadata: 'Government Impersonation',
    description: 'Pretending to be tax authority or social services'
  },
  { 
    number: '+994501234570', 
    name: 'Tech Support Scam', 
    risk: 87, 
    metadata: 'Microsoft Support Spoof',
    description: 'Fake technical support demanding remote access'
  },
  { 
    number: '+994511234571', 
    name: 'Investment Fraud', 
    risk: 91, 
    metadata: 'Crypto Investment Scam',
    description: 'Promising high returns on fake investments'
  }
];

const SPAM_SCENARIOS = [
  { 
    number: '+994551234572', 
    name: 'Unsolicited Insurance', 
    risk: 68, 
    metadata: 'Marketing Pattern',
    description: 'Automated insurance sales calls'
  },
  { 
    number: '+994991234573', 
    name: 'Real Estate Promo', 
    risk: 72, 
    metadata: 'Frequent Cold Call',
    description: 'Property sales and rental promotions'
  },
  { 
    number: '+994701234574', 
    name: 'Survey Bot', 
    risk: 65, 
    metadata: 'Robotic Pattern',
    description: 'Automated market research surveys'
  },
  { 
    number: '+994551234575', 
    name: 'Loan Offers', 
    risk: 71, 
    metadata: 'Telemarketing',
    description: 'Unrequested loan and credit offers'
  },
  { 
    number: '+994771234576', 
    name: 'Service Promotions', 
    risk: 69, 
    metadata: 'Bulk Messaging',
    description: 'Utility and service company promotions'
  }
];

const SAFE_SCENARIOS = [
  { 
    number: '+994501234577', 
    name: 'Family Member', 
    risk: 3, 
    metadata: 'Verified Contact',
    description: 'Known family contact from address book'
  },
  { 
    number: '+994551234578', 
    name: 'Business Partner', 
    risk: 5, 
    metadata: 'Whitelisted Number',
    description: 'Verified business associate'
  }
];
const CHART_DATA = [
  { name: '12:00', calls: 1200, blocked: 340 },
  { name: '14:00', calls: 900, blocked: 210 },
  { name: '16:00', calls: 1500, blocked: 450 },
  { name: '18:00', calls: 1100, blocked: 280 },
];

const ADMIN_AUTH_STORAGE_KEY = 'telcotrust_admin_authed';
// Admin credentials are managed server-side — no hardcoded secrets in client code
const SESSION_STORAGE_KEY = 'telcotrust_session';

type AppUserRole = 'user' | 'admin';
interface AppUser {
  id: string;
  name: string;
  email: string;
  password: string;
  role: AppUserRole;
  createdAt: string;
}

const USERS_DB_STORAGE_KEY = 'telcotrust_users_db';
const USER_ACTIVITY_STORAGE_KEY = 'trustcalll_user_activity_history';
const REPORT_EVENTS_STORAGE_KEY = 'trustcalll_report_events';
const DEVICE_ID_STORAGE_KEY = 'trustcalll_device_id';
const CRITICAL_THREATS_STORAGE_KEY = 'trustcalll_critical_threats';
const GLOBAL_BLACKLIST_STORAGE_KEY = 'trustcalll_global_blacklist_table';
const USER_BLACKLIST_STORAGE_KEY = 'trustcalll_user_blacklist_table';
// API base URL: uses relative path in production (same origin), localhost only for local dev
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

const CROWDSOURCED_REPORT_THRESHOLD = 10;
const CROWDSOURCED_SCAM_RATIO = 0.8;

interface UserActivityEntry {
  id: string;
  userEmail: string;
  action: 'lookup' | 'call' | 'report' | 'block';
  details: string;
  dangerLevel: number;
  createdAt: string;
}

type ReportCategory = 'app_fraud' | 'vishing' | 'caller_id_spoofing' | 'spam' | 'other';

interface ReportEvent {
  id: string;
  number: string;
  category: ReportCategory;
  reporterEmail: string;
  reporterDeviceId: string;
  reporterNetworkSignature: string;
  description?: string;
  createdAt: string;
  evidenceGate: number; // 0.1 / 0.4 / 1.0
  anomalyGate: number; // 0 / 0.3 / 1
  consensusGate: number; // 0.05..1
  weightedImpact: number; // small additive risk signal
  invalidated: boolean;
  reason?: string;
}

interface CompanyNumberEntry {
  number: string;
  name: string;
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function loadUsers(): AppUser[] {
  try {
    const stored = localStorage.getItem(USERS_DB_STORAGE_KEY);
    if (!stored) return [];
    const parsed = JSON.parse(stored);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveUsers(users: AppUser[]): void {
  try {
    localStorage.setItem(USERS_DB_STORAGE_KEY, JSON.stringify(users));
  } catch {
    // ignore storage failures
  }
}


function loadUserActivity(): UserActivityEntry[] {
  try {
    const stored = localStorage.getItem(USER_ACTIVITY_STORAGE_KEY);
    if (!stored) return [];
    const parsed = JSON.parse(stored);
    if (!Array.isArray(parsed)) return [];
    return parsed.map((entry) => ({
      ...entry,
      dangerLevel: typeof entry?.dangerLevel === 'number' ? entry.dangerLevel : 0,
      details:
        typeof entry?.details === 'string'
          ? entry.details.replace(/\s*\(trust\s+\d+(\.\d+)?%\)\s*/gi, ' ').replace(/\s{2,}/g, ' ').trim()
          : '',
    }));
  } catch {
    return [];
  }
}

function saveUserActivity(activity: UserActivityEntry[]): void {
  try {
    localStorage.setItem(USER_ACTIVITY_STORAGE_KEY, JSON.stringify(activity));
  } catch {
    // ignore storage failures
  }
}

function loadReportEvents(): ReportEvent[] {
  try {
    const stored = localStorage.getItem(REPORT_EVENTS_STORAGE_KEY);
    if (!stored) return [];
    const parsed = JSON.parse(stored);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map((e) => ({
        ...e,
        number: typeof e?.number === 'string' ? normalizePhoneNumber(e.number) : e?.number,
      }))
      .filter((e) => typeof e?.number === 'string' && e.number.startsWith('+'));
  } catch {
    return [];
  }
}

function saveReportEvents(events: ReportEvent[]): void {
  try {
    localStorage.setItem(REPORT_EVENTS_STORAGE_KEY, JSON.stringify(events));
  } catch {
    // ignore storage failures
  }
}

function loadCriticalThreats(): CriticalThreat[] {
  try {
    const stored = localStorage.getItem(CRITICAL_THREATS_STORAGE_KEY);
    if (!stored) return [];
    const parsed = JSON.parse(stored);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveCriticalThreats(threats: CriticalThreat[]): void {
  try {
    localStorage.setItem(CRITICAL_THREATS_STORAGE_KEY, JSON.stringify(threats));
  } catch {
    // ignore storage failures
  }
}

function loadGlobalBlacklist(): GlobalBlacklistEntry[] {
  try {
    const stored = localStorage.getItem(GLOBAL_BLACKLIST_STORAGE_KEY);
    if (!stored) return [];
    const parsed = JSON.parse(stored);
    if (!Array.isArray(parsed)) return [];
    return parsed.map((entry) => ({
      ...entry,
      status: 'CRITICAL_BLOCK',
    }));
  } catch {
    return [];
  }
}

function saveGlobalBlacklist(entries: GlobalBlacklistEntry[]): void {
  try {
    localStorage.setItem(GLOBAL_BLACKLIST_STORAGE_KEY, JSON.stringify(entries));
  } catch {
    // ignore storage failures
  }
}

function loadUserBlacklist(): string[] {
  try {
    const stored = localStorage.getItem(USER_BLACKLIST_STORAGE_KEY);
    if (!stored) return [];
    const parsed = JSON.parse(stored);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((entry) => typeof entry === 'string');
  } catch {
    return [];
  }
}

function saveUserBlacklist(entries: string[]): void {
  try {
    localStorage.setItem(USER_BLACKLIST_STORAGE_KEY, JSON.stringify(entries));
  } catch {
    // ignore storage failures
  }
}

// Mock Threat Intelligence Database
const THREAT_INTEL_DB: ThreatIntelEntry[] = [];

// Database entry structure
interface ThreatIntelEntry {
  number: string;
  status: 'safe' | 'suspicious' | 'spam' | 'scam';
  riskScore: number;
  carrier: string;
  source: 'System' | 'User Discovery';
  reportCount: number;
  totalLookups?: number;
  lastUpdated: string;
}

interface CriticalThreat {
  id: string;
  number: string;
  source: 'community' | 'signal_mismatch';
  status: 'pending' | 'confirmed' | 'whitelisted';
  reason: string;
  reportCount: number;
  scamLikeCount: number;
  ratio: number;
  createdAt: string;
  updatedAt: string;
}

interface GlobalBlacklistEntry {
  id: string;
  number: string;
  source: 'admin' | 'community' | 'signal_mismatch';
  status: 'CRITICAL_BLOCK';
  reason: string;
  createdAt: string;
}

// Official whitelist for government/bank numbers
const OFFICIAL_WHITELIST = [
  '+994125', // Government short codes
  '+994126',
  '+994127',
  '+994128',
  '+994129',
  '+994180', // Bank codes
  '+994181',
  '+994182',
  '+994183',
  '+994184'
];

// Initialize database with realistic Azerbaijan numbers (20+ entries with diverse carriers)
const INITIAL_THREAT_INTEL_DB: ThreatIntelEntry[] = [
  // Azercell numbers (10/50/51 prefixes)
  { number: '+994501234567', status: 'safe', riskScore: 5, carrier: 'Azercell', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994501234568', status: 'scam', riskScore: 92, carrier: 'Azercell', source: 'System', reportCount: 3, lastUpdated: new Date().toISOString() },
  { number: '+994501234569', status: 'spam', riskScore: 78, carrier: 'Azercell', source: 'System', reportCount: 1, lastUpdated: new Date().toISOString() },
  { number: '+994501234570', status: 'suspicious', riskScore: 45, carrier: 'Azercell', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994501234571', status: 'safe', riskScore: 3, carrier: 'Azercell', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994501234572', status: 'scam', riskScore: 89, carrier: 'Azercell', source: 'System', reportCount: 2, lastUpdated: new Date().toISOString() },
  { number: '+994501234573', status: 'safe', riskScore: 8, carrier: 'Azercell', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994501234574', status: 'spam', riskScore: 72, carrier: 'Azercell', source: 'System', reportCount: 1, lastUpdated: new Date().toISOString() },
  { number: '+994501234575', status: 'suspicious', riskScore: 38, carrier: 'Azercell', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994501234576', status: 'scam', riskScore: 95, carrier: 'Azercell', source: 'System', reportCount: 4, lastUpdated: new Date().toISOString() },
  { number: '+994501234577', status: 'safe', riskScore: 12, carrier: 'Azercell', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994501234578', status: 'spam', riskScore: 65, carrier: 'Azercell', source: 'System', reportCount: 1, lastUpdated: new Date().toISOString() },
  { number: '+994501234579', status: 'suspicious', riskScore: 52, carrier: 'Azercell', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994501234580', status: 'scam', riskScore: 87, carrier: 'Azercell', source: 'System', reportCount: 2, lastUpdated: new Date().toISOString() },
  { number: '+994501234581', status: 'safe', riskScore: 7, carrier: 'Azercell', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994511234582', status: 'spam', riskScore: 81, carrier: 'Azercell', source: 'System', reportCount: 1, lastUpdated: new Date().toISOString() },
  { number: '+994511234583', status: 'suspicious', riskScore: 41, carrier: 'Azercell', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994511234584', status: 'scam', riskScore: 93, carrier: 'Azercell', source: 'System', reportCount: 3, lastUpdated: new Date().toISOString() },
  { number: '+994511234585', status: 'safe', riskScore: 9, carrier: 'Azercell', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994101234586', status: 'spam', riskScore: 76, carrier: 'Azercell', source: 'System', reportCount: 1, lastUpdated: new Date().toISOString() },
  { number: '+994101234587', status: 'suspicious', riskScore: 47, carrier: 'Azercell', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994101234588', status: 'scam', riskScore: 91, carrier: 'Azercell', source: 'System', reportCount: 2, lastUpdated: new Date().toISOString() },
  { number: '+994101234589', status: 'safe', riskScore: 4, carrier: 'Azercell', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994101234590', status: 'spam', riskScore: 69, carrier: 'Azercell', source: 'System', reportCount: 1, lastUpdated: new Date().toISOString() },
  { number: '+994101234591', status: 'suspicious', riskScore: 33, carrier: 'Azercell', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  
  // Bakcell numbers (55/99 prefixes)
  { number: '+994551234592', status: 'safe', riskScore: 6, carrier: 'Bakcell', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994551234593', status: 'suspicious', riskScore: 42, carrier: 'Bakcell', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994551234594', status: 'spam', riskScore: 73, carrier: 'Bakcell', source: 'System', reportCount: 1, lastUpdated: new Date().toISOString() },
  { number: '+994991234595', status: 'safe', riskScore: 8, carrier: 'Bakcell', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994991234596', status: 'scam', riskScore: 88, carrier: 'Bakcell', source: 'System', reportCount: 2, lastUpdated: new Date().toISOString() },
  
  // Nar numbers (70/77 prefixes)
  { number: '+994701234597', status: 'safe', riskScore: 5, carrier: 'Nar', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994701234598', status: 'suspicious', riskScore: 39, carrier: 'Nar', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994771234599', status: 'safe', riskScore: 7, carrier: 'Nar', source: 'System', reportCount: 0, lastUpdated: new Date().toISOString() },
  { number: '+994771234600', status: 'spam', riskScore: 71, carrier: 'Nar', source: 'System', reportCount: 1, lastUpdated: new Date().toISOString() },
];

// LocalStorage management functions
const DB_STORAGE_KEY = 'telcotrust_threat_intel_db_v2';

function loadDatabase(): ThreatIntelEntry[] {
  try {
    const stored = localStorage.getItem(DB_STORAGE_KEY);
    if (stored) {
      const parsed = JSON.parse(stored);
      return Array.isArray(parsed) ? parsed : [];
    }
  } catch (error) {
    console.warn('Failed to load database from localStorage:', error);
  }
  // Start with an empty table unless user generates new entries.
  return [];
}

function saveDatabase(db: ThreatIntelEntry[]): void {
  try {
    localStorage.setItem(DB_STORAGE_KEY, JSON.stringify(db));
  } catch (error) {
    console.error('Failed to save database to localStorage:', error);
  }
}

function calculateReportPercentage(reportCount: number, totalLookups: number): number {
  const safeReports = Math.max(0, Number(reportCount || 0));
  // Product rule: report percentage always increases by +10 per report.
  return Math.min(100, safeReports * 10);
}

// Smart Number Normalization Function (CRITICAL)
function normalizePhoneNumber(input: string): string {
  // Remove all non-digit characters
  const digitsOnly = input.replace(/\D/g, '');
  const trimmed = input.trim();
  
  // Handle different input formats
  if (digitsOnly.startsWith('994')) {
    // Already has country code, just add +
    return `+${digitsOnly}`;
  } else if (digitsOnly.length === 9) {
    // Local format without country code (e.g., 556778787)
    return `+994${digitsOnly}`;
  } else if (digitsOnly.length === 10 && digitsOnly.startsWith('0')) {
    // Local format with leading 0 (e.g., 0556778787)
    return `+994${digitsOnly.substring(1)}`;
  } else if (digitsOnly.length === 12 && digitsOnly.startsWith('994')) {
    // International format without + (e.g., 994556778787)
    return `+${digitsOnly}`;
  }

  // Generic international numbers (E.164-like): keep as +<digits>
  if ((trimmed.startsWith('+') || trimmed.startsWith('00')) && digitsOnly.length >= 8 && digitsOnly.length <= 15) {
    return `+${digitsOnly}`;
  }
  if (digitsOnly.length >= 8 && digitsOnly.length <= 15) {
    return `+${digitsOnly}`;
  }
  
  // Return as-is if it doesn't match expected patterns
  return input;
}

// Carrier detection function (Updated per requirements)
function detectCarrier(phoneNumber: string): string {
  if (!phoneNumber.startsWith('+994')) {
    return 'International';
  }
  
  const prefix = phoneNumber.substring(4, 6);
  switch (prefix) {
    case '10':
    case '50':
    case '51':
      return 'Azercell';
    case '55':
    case '99':
      return 'Bakcell';
    case '70':
    case '77':
      return 'Nar';
    default:
      return 'Unknown Carrier';
  }
}

// Pattern analysis for risk assessment
function analyzePatterns(phoneNumber: string): { hasRepeatingDigits: boolean; isOfficial: boolean } {
  // Check for 4+ repeating digits
  const hasRepeatingDigits = /(\d)\1{3,}/.test(phoneNumber.replace('+994', ''));
  
  // Check if it's an official number
  const isOfficial = OFFICIAL_WHITELIST.some(official => phoneNumber.startsWith(official));
  
  return { hasRepeatingDigits, isOfficial };
}

// Advanced rule-based risk analysis engine
function calculateAdvancedRiskScore(phoneNumber: string): { status: 'safe' | 'suspicious' | 'spam' | 'scam', riskScore: number, carrier: string } {
  const carrier = detectCarrier(phoneNumber);
  const { hasRepeatingDigits, isOfficial } = analyzePatterns(phoneNumber);
  
  // Official numbers get 0% risk
  if (isOfficial) {
    return { status: 'safe', riskScore: 0, carrier };
  }
  
  // International numbers get high suspicion
  if (carrier === 'International') {
    return { status: 'suspicious', riskScore: 75, carrier };
  }
  
  // Numbers with repeating digits are likely spam
  if (hasRepeatingDigits) {
    return { status: 'spam', riskScore: 85, carrier };
  }
  
  // Generate consistent risk score based on phone number for new entries
  let baseRisk = 0;
  
  // Create a seed from the phone number for consistent randomization
  let seed = 0;
  for (let i = 0; i < phoneNumber.length; i++) {
    seed += phoneNumber.charCodeAt(i);
  }
  
  // Simple seeded random function
  const seededRandom = (min: number, max: number): number => {
    seed = (seed * 9301 + 49297) % 233280;
    const rnd = seed / 233280;
    return Math.floor(min + rnd * (max - min + 1));
  };
  
  // Different risk profiles based on carrier
  switch (carrier) {
    case 'Azercell':
      baseRisk = seededRandom(0, 40); // Generally safer
      break;
    case 'Bakcell':
      baseRisk = seededRandom(10, 60); // Moderate risk
      break;
    case 'Nar':
      baseRisk = seededRandom(5, 50); // Mixed risk
      break;
    default:
      baseRisk = seededRandom(0, 30); // Default safe
  }
  
  // Determine status based on risk score
  let status: 'safe' | 'suspicious' | 'spam' | 'scam';
  if (baseRisk >= 80) status = 'scam';
  else if (baseRisk >= 60) status = 'spam';
  else if (baseRisk >= 30) status = 'suspicious';
  else status = 'safe';
  
  return { status, riskScore: baseRisk, carrier };
}

// Function to calculate consistent risk score based on status and phone number
function calculateRiskScore(status: string, phoneNumber: string): number {
  // Create a seed from the phone number for consistent randomization
  let seed = 0;
  for (let i = 0; i < phoneNumber.length; i++) {
    seed += phoneNumber.charCodeAt(i);
  }
  
  // Simple seeded random function
  const seededRandom = (min: number, max: number): number => {
    seed = (seed * 9301 + 49297) % 233280;
    const rnd = seed / 233280;
    return Math.floor(min + rnd * (max - min + 1));
  };

  switch (status) {
    case 'scam':
      return seededRandom(85, 99);
    case 'spam':
      return seededRandom(60, 84);
    case 'suspicious':
      return seededRandom(30, 59);
    case 'safe':
      return seededRandom(0, 15);
    default:
      return seededRandom(0, 15);
  }
}

// Validation function for E.164-like phone numbers
function validatePhoneNumber(number: string): boolean {
  const regex = /^\+\d{8,15}$/;
  return regex.test(number);
}

function maskPhoneNumber(number: string): string {
  const digits = number.replace(/\D/g, '');
  if (!digits.startsWith('994') || digits.length !== 12) {
    return number;
  }

  const rest = digits.slice(3); // 9 digits after the country code
  const prefix = rest.slice(0, 2);
  const hidden = '***';
  const mid = rest.slice(5, 7);
  const tail = rest.slice(7);

  return `+994 ${prefix} ${hidden} ${mid} ${tail}`;
}

const REPORT_CATEGORY_META: Record<ReportCategory, { label: string; description: string; badgeClass: string }> = {
  app_fraud: {
    label: 'APP fraud',
    description: 'Fraud via mobile apps or payment apps (social engineering, fake apps, in-app scams).',
    badgeClass: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  },
  vishing: {
    label: 'Vishing',
    description: 'Voice phishing: caller tries to trick you into sharing OTPs, passwords, or personal/banking data.',
    badgeClass: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  },
  caller_id_spoofing: {
    label: 'Caller ID spoofing',
    description: 'Caller fakes the displayed number (bank/government/known contact) to appear legitimate.',
    badgeClass: 'bg-red-500/15 text-red-300 border-red-500/30',
  },
  spam: {
    label: 'Spam',
    description: 'Unwanted marketing/robocalls or repeated unsolicited calls.',
    badgeClass: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30',
  },
  other: {
    label: 'Other',
    description: 'Anything that doesn’t fit the main categories.',
    badgeClass: 'bg-slate-500/15 text-slate-300 border-white/10',
  },
};

export default function App() {
  const [activeTab, setActiveTab] = useState<'consumer' | 'operator' | 'demo'>('demo');
  const [isIncomingCall, setIsIncomingCall] = useState(false);
  const [currentCall, setCurrentCall] = useState<CallEvent | null>(null);
  const [demoState, setDemoState] = useState<'idle' | 'ringing' | 'blocked' | 'allowed'>('idle');
  const [bankAlert, setBankAlert] = useState<string | null>(null);
  const [currentScenario, setCurrentScenario] = useState<any>(null);
  const [threatIntelDB, setThreatIntelDB] = useState<ThreatIntelEntry[]>([]);
  const [isAdminView, setIsAdminView] = useState(false);
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginMessage, setLoginMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [appView, setAppView] = useState<'login' | 'register' | 'app'>('login');
  const [currentUser, setCurrentUser] = useState<{ email: string; role: AppUserRole | 'superadmin' } | null>(null);
  const [usersDb, setUsersDb] = useState<AppUser[]>([]);
  const [userActivity, setUserActivity] = useState<UserActivityEntry[]>([]);
  const [reportEvents, setReportEvents] = useState<ReportEvent[]>([]);
  const [companyNumbers, setCompanyNumbers] = useState<CompanyNumberEntry[]>([]);
  const [criticalThreats, setCriticalThreats] = useState<CriticalThreat[]>([]);
  const [globalBlacklist, setGlobalBlacklist] = useState<GlobalBlacklistEntry[]>([]);
  const [userBlacklist, setUserBlacklist] = useState<string[]>(() => loadUserBlacklist());
  const [trustGuardNotice, setTrustGuardNotice] = useState<string | null>(null);
  const [reportCenterCategoryFilter, setReportCenterCategoryFilter] = useState<'all' | 'bank' | 'delivery' | 'personal'>('all');
  const [expandedReportCenterNumber, setExpandedReportCenterNumber] = useState<string | null>(null);
  const [adminToastMessage, setAdminToastMessage] = useState<string | null>(null);
  const [deviceId, setDeviceId] = useState('');
  const [activityFilter, setActivityFilter] = useState<'all' | 'blocked' | 'reported' | 'lookups' | 'calls'>('all');
  const [activitySort, setActivitySort] = useState<'time' | 'danger'>('time');
  const [regName, setRegName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regMessage, setRegMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Admin access is handled only via the main Login screen (super-admin fixed credentials).

  const persistSession = (session: { email: string; role: AppUserRole | 'superadmin' }) => {
    setCurrentUser(session);
    setIsAdminView(session.role === 'superadmin');
    try {
      localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
      if (session.role === 'superadmin') {
        localStorage.setItem(ADMIN_AUTH_STORAGE_KEY, 'true');
      } else {
        localStorage.removeItem(ADMIN_AUTH_STORAGE_KEY);
      }
    } catch {
      // ignore storage failures
    }
  };

  const clearSession = () => {
    setCurrentUser(null);
    setIsAdminView(false);
    try {
      localStorage.removeItem(SESSION_STORAGE_KEY);
      localStorage.removeItem(ADMIN_AUTH_STORAGE_KEY);
    } catch {
      // ignore storage failures
    }
  };

  const appendUserActivity = (entry: Omit<UserActivityEntry, 'id' | 'userEmail' | 'createdAt'>) => {
    if (!currentUser?.email) return;

    const newEntry: UserActivityEntry = {
      id: crypto?.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2),
      userEmail: normalizeEmail(currentUser.email),
      action: entry.action,
      details: entry.details,
      dangerLevel: entry.dangerLevel,
      createdAt: new Date().toISOString(),
    };

    const updated = [newEntry, ...userActivity];
    setUserActivity(updated);
    saveUserActivity(updated);
  };

  const appendReportEvent = (event: Omit<ReportEvent, 'id' | 'createdAt'>) => {
    const newEvent: ReportEvent = {
      ...event,
      id: crypto?.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2),
      createdAt: new Date().toISOString(),
    };
    const updated = [newEvent, ...reportEvents];
    setReportEvents(updated);
    saveReportEvents(updated);
    return { newEvent, updatedEvents: updated };
  };

  const handlePrimaryLogin = async () => {
    setLoginMessage(null);
    const email = normalizeEmail(loginEmail);
    const password = loginPassword;

    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        const payload = await response.json().catch(() => ({} as any));
        setLoginMessage({ type: 'error', text: payload?.error || 'Invalid credentials' });
        return;
      }

      const payload = await response.json();
      const userRole = payload?.user?.role as AppUserRole | 'superadmin' | undefined;
      const userEmail = normalizeEmail(payload?.user?.email || email);

      if (!userRole || (userRole !== 'user' && userRole !== 'admin' && userRole !== 'superadmin')) {
        setLoginMessage({ type: 'error', text: 'Invalid server response' });
        return;
      }

      if (userRole === 'admin') {
        setLoginMessage({ type: 'error', text: 'Admin login is restricted. Use super-admin credentials.' });
        return;
      }

      setIsAdminView(userRole === 'superadmin');
      try {
        if (userRole === 'superadmin') {
          localStorage.setItem(ADMIN_AUTH_STORAGE_KEY, 'true');
        } else {
          localStorage.removeItem(ADMIN_AUTH_STORAGE_KEY);
        }
      } catch {
        // ignore storage failures
      }

      persistSession({ email: userEmail, role: userRole });
      setAppView('app');
      setActiveTab(userRole === 'user' ? 'consumer' : 'operator');
      setLoginPassword('');
    } catch {
      setLoginMessage({ type: 'error', text: 'API unavailable. Please try again.' });
    }
  };

  const handleLogout = () => {
    clearSession();
    setIsAdminView(false);
    try {
      localStorage.removeItem(ADMIN_AUTH_STORAGE_KEY);
    } catch {
      // ignore storage failures
    }
    setLoginEmail('');
    setLoginPassword('');
    setLoginMessage(null);
    setAppView('login');
  };

  // Load database on component mount
  useEffect(() => {
    setThreatIntelDB(loadDatabase());
  }, []);

  useEffect(() => {
    fetch('/company-numbers.json')
      .then((res) => (res.ok ? res.json() : []))
      .then((data) => {
        if (!Array.isArray(data)) return;
        const normalized = data
          .map((entry: any) => ({
            number: typeof entry?.number === 'string' ? normalizePhoneNumber(entry.number) : '',
            name: typeof entry?.name === 'string' ? entry.name : 'Company Number',
          }))
          .filter((entry) => validatePhoneNumber(entry.number));
        setCompanyNumbers(normalized);
      })
      .catch(() => {
        setCompanyNumbers([]);
      });
  }, []);

  // Restore Admin View from localStorage
  useEffect(() => {
    try {
      setIsAdminView(localStorage.getItem(ADMIN_AUTH_STORAGE_KEY) === 'true');
    } catch {
      setIsAdminView(false);
    }
  }, []);

  // Load users DB on mount
  useEffect(() => {
    setUsersDb(loadUsers());
  }, []);

  // Load user activity history on mount
  useEffect(() => {
    setUserActivity(loadUserActivity());
  }, []);

  useEffect(() => {
    setReportEvents(loadReportEvents());
  }, []);

  useEffect(() => {
    setCriticalThreats(loadCriticalThreats());
  }, []);

  useEffect(() => {
    setGlobalBlacklist(loadGlobalBlacklist());
  }, []);

  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key === CRITICAL_THREATS_STORAGE_KEY) {
        setCriticalThreats(loadCriticalThreats());
      }
      if (event.key === GLOBAL_BLACKLIST_STORAGE_KEY) {
        setGlobalBlacklist(loadGlobalBlacklist());
      }
      if (event.key === REPORT_EVENTS_STORAGE_KEY) {
        setReportEvents(loadReportEvents());
      }
      if (event.key === DB_STORAGE_KEY) {
        setThreatIntelDB(loadDatabase());
      }
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  useEffect(() => {
    const activeNumbers = new Set(
      criticalThreats.filter((t) => t.status !== 'whitelisted').map((t) => t.number)
    );
    if (activeNumbers.size === 0) return;
    const nowIso = new Date().toISOString();
    let changed = false;
    const nextDb = threatIntelDB.map((entry) => {
      if (!activeNumbers.has(entry.number)) return entry;
      if (entry.status === 'scam' && entry.riskScore === 100) return entry;
      changed = true;
      return {
        ...entry,
        status: 'scam' as const,
        riskScore: 100,
        source: 'System' as const,
        lastUpdated: nowIso,
      };
    });
    if (changed) {
      updateDatabase(nextDb);
    }
  }, [criticalThreats]);

  useEffect(() => {
    try {
      const stored = localStorage.getItem(DEVICE_ID_STORAGE_KEY);
      if (stored) {
        setDeviceId(stored);
        return;
      }
      const generated = crypto?.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
      localStorage.setItem(DEVICE_ID_STORAGE_KEY, generated);
      setDeviceId(generated);
    } catch {
      setDeviceId('unknown-device');
    }
  }, []);

  // Restore session on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(SESSION_STORAGE_KEY);
      if (!stored) return;
      const parsed = JSON.parse(stored);
      if (parsed && typeof parsed.email === 'string' && typeof parsed.role === 'string') {
        const restoredRole = parsed.role as AppUserRole | 'superadmin';
        setCurrentUser({ email: parsed.email, role: restoredRole });
        setIsAdminView(restoredRole === 'superadmin');
        setAppView('app');
        setActiveTab(restoredRole === 'superadmin' ? 'operator' : 'consumer');
      }
    } catch {
      // ignore
    }
  }, []);

  const canViewOperatorActivity = isAdminView || currentUser?.role === 'superadmin' || currentUser?.role === 'admin';
  const canViewPersonalDashboard = !canViewOperatorActivity;

  useEffect(() => {
    if (activeTab === 'operator' && !canViewOperatorActivity) {
      setActiveTab('consumer');
    }
  }, [activeTab, canViewOperatorActivity]);

  useEffect(() => {
    if (activeTab === 'consumer' && !canViewPersonalDashboard) {
      setActiveTab('operator');
    }
  }, [activeTab, canViewOperatorActivity, canViewPersonalDashboard]);

  const handleRegisterSubmit = async () => {
    setRegMessage(null);

    const name = regName.trim();
    const email = normalizeEmail(regEmail);
    const password = regPassword;
    const role: AppUserRole = 'user';

    if (!name) {
      setRegMessage({ type: 'error', text: 'Name is required' });
      return;
    }
    if (!email || !email.includes('@')) {
      setRegMessage({ type: 'error', text: 'Valid email is required' });
      return;
    }
    if (password.length < 6) {
      setRegMessage({ type: 'error', text: 'Password must be at least 6 characters' });
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password }),
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({} as any));
        setRegMessage({ type: 'error', text: payload?.error || 'Could not save user to database' });
        return;
      }
    } catch {
      setRegMessage({ type: 'error', text: 'API unavailable. User was not saved to database.' });
      return;
    }

    const newUser: AppUser = {
      id: crypto?.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2),
      name,
      email,
      password,
      role,
      createdAt: new Date().toISOString(),
    };

    const updated = [newUser, ...usersDb];
    setUsersDb(updated);
    saveUsers(updated);

    setRegMessage({ type: 'success', text: 'User registered successfully' });
    setRegName('');
    setRegEmail('');
    setRegPassword('');
    setIsAdminView(false);
    try {
      localStorage.removeItem(ADMIN_AUTH_STORAGE_KEY);
    } catch {
      // ignore storage failures
    }
    persistSession({ email, role: 'user' });
    setAppView('app');
    setActiveTab('consumer');
  };

  // Function to update database and persist to localStorage
  const updateDatabase = (newDB: ThreatIntelEntry[]) => {
    setThreatIntelDB(newDB);
    saveDatabase(newDB);
    void syncNumbersToServer(newDB);
  };

  const startDemo = (type: 'safe' | 'scam' | 'spam') => {
    let scenario;
    
    if (type === 'safe') {
      scenario = SAFE_SCENARIOS[Math.floor(Math.random() * SAFE_SCENARIOS.length)];
    } else if (type === 'scam') {
      scenario = SCAM_SCENARIOS[Math.floor(Math.random() * SCAM_SCENARIOS.length)];
      // Trigger bank alert for scam scenarios
      setBankAlert(`PASHA Bank alerted: Transaction hold active for target account`);
      setTimeout(() => setBankAlert(null), 8000); // Clear after 8 seconds
    } else if (type === 'spam') {
      scenario = SPAM_SCENARIOS[Math.floor(Math.random() * SPAM_SCENARIOS.length)];
      // No bank alert for spam
      setBankAlert(null);
    }
    
    setCurrentScenario(scenario);
    
    // Create call event from scenario
    const callEvent = {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toISOString(),
      callerNumber: scenario.number,
      callerName: scenario.name,
      riskScore: scenario.risk,
      riskLevel: type === 'safe' ? 'safe' : type === 'scam' ? 'dangerous' : 'suspicious',
      status: type === 'safe' ? 'allowed' : type === 'scam' ? 'blocked' : 'screening',
      intent: type,
      factors: [
        { name: 'STIR/SHAKEN', score: type === 'safe' ? 0 : 0.9, impact: type === 'safe' ? 'low' : 'high', reason: scenario.metadata },
        { name: 'Pattern Analysis', score: type === 'safe' ? 0 : 0.7, impact: type === 'safe' ? 'low' : 'medium', reason: scenario.description }
      ],
      metadata: {
        userAgent: type === 'safe' ? 'BroadSoft-Asterisk' : 'MicroSIP/3.21',
        sourceIp: type === 'safe' ? '82.196.1.1' : '185.234.12.1',
        via: type === 'safe' ? ['SIP/2.0/UDP 10.0.0.1'] : ['SIP/2.0/TLS 192.168.1.5', 'SIP/2.0/UDP 45.1.2.3'],
        contact: type === 'safe' ? '<sip:caller@provider.com>' : '<sip:scammer@anonymous.org>',
        routingHops: type === 'safe' ? 2 : 5,
        isStirShakenVerified: type === 'safe'
      }
    };
    
    setCurrentCall(callEvent);
    setDemoState('ringing');
    setIsIncomingCall(true);

    appendUserActivity({
      action: 'call',
      details: `Simulated call: ${scenario.number} (${scenario.name}) — ${type.toUpperCase()} scenario`,
      dangerLevel: scenario.risk,
    });
  };

  const [lookupNumber, setLookupNumber] = useState('');
  const [lookupState, setLookupState] = useState<'idle' | 'searching' | 'done'>('idle');
  const [lookupResult, setLookupResult] = useState<{ risk: number, msg: string, number?: string, carrier?: string, reportCount?: number } | null>(null);
  const [protocolIdentity, setProtocolIdentity] = useState('VERIFIED');
  const [headerMismatch, setHeaderMismatch] = useState(false);
  const [isReportComposerOpen, setIsReportComposerOpen] = useState(false);
  const [reportDraftDescription, setReportDraftDescription] = useState('');
  const [reportDraftCategory, setReportDraftCategory] = useState<ReportCategory | ''>('');

  const syncNumbersToServer = async (items: ThreatIntelEntry[]) => {
    try {
      await fetch(`${API_BASE_URL}/api/sync/numbers`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          items: items.map((entry) => ({
            number: entry.number,
            status: entry.status,
            riskScore: entry.riskScore,
            carrier: entry.carrier,
            source: entry.source,
            reportCount: Math.max(0, Number(entry.reportCount || 0)),
            totalLookups: Math.max(0, Number(entry.totalLookups || 0)),
            lastUpdated: entry.lastUpdated,
          })),
        }),
      });
    } catch {
      // keep UI usable even if API is temporarily down
    }
  };

  const getUserAgeDays = (email: string) => {
    const user = usersDb.find((u) => normalizeEmail(u.email) === normalizeEmail(email));
    if (!user) return 0;
    return (Date.now() - new Date(user.createdAt).getTime()) / (1000 * 60 * 60 * 24);
  };

  const getReportEvidenceGate = (entry: ThreatIntelEntry) => {
    const { hasRepeatingDigits } = analyzePatterns(entry.number);
    const isCarrierRisky = entry.carrier === 'International' || entry.carrier === 'Unknown Carrier';
    const routingAnomaly = entry.status === 'spam' || entry.status === 'scam' || entry.riskScore >= 70;

    const supportSignals = [hasRepeatingDigits, isCarrierRisky, routingAnomaly].filter(Boolean).length;
    if (supportSignals >= 2) return 1.0;
    if (supportSignals === 1) return 0.4;
    return 0.1;
  };

  const getReporterAnomalyScore = (email: string, targetNumber: string) => {
    const now = Date.now();
    const normalizedEmail = normalizeEmail(email);
    const last10m = reportEvents.filter(
      (e) => normalizeEmail(e.reporterEmail) === normalizedEmail &&
      now - new Date(e.createdAt).getTime() <= 10 * 60 * 1000
    );
    const last24h = reportEvents.filter(
      (e) => normalizeEmail(e.reporterEmail) === normalizedEmail &&
      now - new Date(e.createdAt).getTime() <= 24 * 60 * 60 * 1000
    );
    const deviceLast10m = reportEvents.filter(
      (e) => e.reporterDeviceId === deviceId &&
      now - new Date(e.createdAt).getTime() <= 10 * 60 * 1000
    );
    const sameTargetFromNewUsers = reportEvents.filter((e) => {
      if (e.number !== targetNumber) return false;
      if (now - new Date(e.createdAt).getTime() > 5 * 60 * 1000) return false;
      return getUserAgeDays(e.reporterEmail) < 3;
    }).length;

    let score = 0;
    if (last10m.length >= 5) score += 0.35;
    if (last24h.length >= 20) score += 0.25;
    if (deviceLast10m.length >= 8) score += 0.35;
    if (sameTargetFromNewUsers >= 3) score += 0.25;
    if (getUserAgeDays(email) < 1) score += 0.15;
    return Math.min(1, score);
  };

  const getConsensusGate = (number: string) => {
    const now = Date.now();
    const recent = reportEvents
      .filter((e) => !e.invalidated && e.number === number && now - new Date(e.createdAt).getTime() <= 24 * 60 * 60 * 1000);
    if (recent.length === 0) return 0.05;

    const uniqueUsers = new Set(recent.map((e) => normalizeEmail(e.reporterEmail))).size;
    const uniqueDevices = new Set(recent.map((e) => e.reporterDeviceId)).size;
    const times = recent.map((e) => new Date(e.createdAt).getTime()).sort((a, b) => a - b);
    const spreadMin = times.length > 1 ? (times[times.length - 1] - times[0]) / (1000 * 60) : 0;

    const diversityScore = Math.min(1, uniqueUsers / 3) * 0.6 + Math.min(1, uniqueDevices / 3) * 0.4;
    const timeDistributionScore = Math.min(1, spreadMin / 10);
    return Math.max(0.05, diversityScore * timeDistributionScore);
  };

  const mapRiskToStatus = (risk: number, allowScam: boolean): 'safe' | 'suspicious' | 'spam' | 'scam' => {
    if (allowScam && risk >= 85) return 'scam';
    if (risk >= 60) return 'spam';
    if (risk >= 30) return 'suspicious';
    return 'safe';
  };

  const getReportRiskSignal = (number: string) => {
    const sum = reportEvents
      .filter((e) => e.number === number && !e.invalidated)
      .reduce((acc, e) => acc + e.weightedImpact, 0);
    return Math.min(20, sum);
  };

  const hasReportedNumberToday = (number: string) => {
    if (!currentUser?.email) return false;
    const normalizedReporter = normalizeEmail(currentUser.email);
    const now = Date.now();
    return reportEvents.some(
      (e) =>
        normalizeEmail(e.reporterEmail) === normalizedReporter &&
        e.number === number &&
        now - new Date(e.createdAt).getTime() <= 24 * 60 * 60 * 1000
    );
  };

  const getCompanyByNumber = (number: string) => {
    return companyNumbers.find((entry) => entry.number === number) || null;
  };

  const SCAM_LIKE_REPORT_CATEGORIES: ReportCategory[] = ['app_fraud', 'vishing', 'caller_id_spoofing'];

  const getActiveCriticalThreat = (number: string) =>
    criticalThreats.find((t) => t.number === number && t.status !== 'whitelisted') || null;

  const setCriticalThreatAndPersist = (next: CriticalThreat[]) => {
    setCriticalThreats(next);
    saveCriticalThreats(next);
  };

  const upsertCriticalThreat = (
    input: Omit<CriticalThreat, 'id' | 'createdAt' | 'updatedAt'>,
    opts?: { notify?: boolean }
  ) => {
    const existing = criticalThreats.find((t) => t.number === input.number);
    const nowIso = new Date().toISOString();
    let next: CriticalThreat[];
    if (existing) {
      next = criticalThreats.map((t) =>
        t.number === input.number
          ? {
              ...t,
              ...input,
              // Do not overwrite createdAt/id on updates
              updatedAt: nowIso,
            }
          : t
      );
    } else {
      next = [
        {
          id: crypto?.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2),
          createdAt: nowIso,
          updatedAt: nowIso,
          ...input,
        },
        ...criticalThreats,
      ];
    }
    setCriticalThreatAndPersist(next);
    if (opts?.notify) {
      setTrustGuardNotice(`TrustCall Guard: ${input.number} auto-blacklisted (${input.reason})`);
    }
  };

  const forceGlobalBlock = (number: string) => {
    const normalized = normalizePhoneNumber(number);
    const nowIso = new Date().toISOString();
    const exists = threatIntelDB.some((e) => e.number === normalized);

    const updatedDB = (exists ? threatIntelDB : [
      ...threatIntelDB,
      {
        number: normalized,
        status: 'suspicious' as const,
        riskScore: 0,
        carrier: detectCarrier(normalized),
        source: 'System' as const,
        reportCount: 0,
        lastUpdated: nowIso,
      } satisfies ThreatIntelEntry,
    ]).map((entry) => {
      if (entry.number !== normalized) return entry;
      return {
        ...entry,
        status: 'scam' as const,
        riskScore: 100,
        source: 'System' as const,
        lastUpdated: nowIso,
      };
    });
    updateDatabase(updatedDB);
    return updatedDB;
  };

  const isGloballyBlacklisted = (number: string) => globalBlacklist.some((e) => e.number === number);

  const addToGlobalBlacklist = (
    number: string,
    source: GlobalBlacklistEntry['source'],
    reason: string
  ) => {
    if (isGloballyBlacklisted(number)) return;
    const next: GlobalBlacklistEntry[] = [
      {
        id: crypto?.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2),
        number,
        source,
        status: 'CRITICAL_BLOCK',
        reason,
        createdAt: new Date().toISOString(),
      },
      ...globalBlacklist,
    ];
    setGlobalBlacklist(next);
    saveGlobalBlacklist(next);
  };

  const classifyReportCenterCategory = (number: string, comments: string[]) => {
    const text = `${number} ${comments.join(' ')}`.toLowerCase();
    const bankHints = ['bank', 'card', 'payment', 'iban', 'kapital', 'otp'];
    const deliveryHints = ['delivery', 'courier', 'cargo', 'package', 'shipment'];
    if (bankHints.some((k) => text.includes(k))) return 'bank' as const;
    if (deliveryHints.some((k) => text.includes(k))) return 'delivery' as const;
    return 'personal' as const;
  };

  const reportCenterRows = threatIntelDB
    .map((entry) => {
      const events = reportEvents.filter((e) => e.number === entry.number && !e.invalidated);
      const totalReports = Math.max(0, Number(entry.reportCount || 0));
      const totalLookups = Math.max(0, Number(entry.totalLookups || 0));
      const reportPercentage = calculateReportPercentage(totalReports, totalLookups);
      const scamLikeCount = events.filter((e) => SCAM_LIKE_REPORT_CATEGORIES.includes(e.category)).length;
      const scamRatio = totalReports > 0 ? (scamLikeCount / totalReports) * 100 : 0;
      const lastReportedAt = events.length
        ? events
            .map((e) => new Date(e.createdAt).getTime())
            .sort((a, b) => b - a)[0]
        : null;
      const comments = events.map((e) => e.description?.trim()).filter(Boolean) as string[];
      const categoryTag = classifyReportCenterCategory(entry.number, comments);
      return {
        number: entry.number,
        totalReports,
        totalLookups,
        reportPercentage,
        scamLikeCount,
        scamRatio,
        lastReportedAt,
        comments,
        categoryTag,
        criticalActionRequired: totalReports > 5 && scamRatio > 80,
      };
    })
    .filter((row) => (reportCenterCategoryFilter === 'all' ? true : row.categoryTag === reportCenterCategoryFilter))
    .sort((a, b) => b.totalReports - a.totalReports || (b.lastReportedAt || 0) - (a.lastReportedAt || 0));

  const riskPriority = (status: ThreatIntelEntry['status']) => {
    if (status === 'scam') return 4;
    if (status === 'spam') return 3;
    if (status === 'suspicious') return 2;
    return 1;
  };

  // Report percentage is based on reportCount / totalLookups.
  const getReportCountForRisk = (number: string) => {
    const normalized = normalizePhoneNumber(number);
    const entry = threatIntelDB.find((e) => normalizePhoneNumber(e.number) === normalized);
    return Math.max(0, Number(entry?.reportCount || 0));
  };

  const getReportPercent = (entry: ThreatIntelEntry) => {
    const totalLookups = Math.max(0, Number(entry.totalLookups || 0));
    const reportCount = Math.max(Number(entry.reportCount || getReportCountForRisk(entry.number)), 0);
    return calculateReportPercentage(reportCount, totalLookups);
  };

  const registryRowsSorted = [...threatIntelDB]
    .filter((entry) => !isGloballyBlacklisted(entry.number))
    .sort((a, b) => {
      const byStatus = riskPriority(b.status) - riskPriority(a.status);
      if (byStatus !== 0) return byStatus;
      const byReportsPct = getReportPercent(b) - getReportPercent(a);
      if (byReportsPct !== 0) return byReportsPct;
      if (b.riskScore !== a.riskScore) return b.riskScore - a.riskScore;
      return new Date(b.lastUpdated).getTime() - new Date(a.lastUpdated).getTime();
    });

  const evaluateCrowdsourcedCriticality = (number: string, events: ReportEvent[]) => {
    const valid = events.filter((e) => e.number === number && !e.invalidated);
    if (valid.length < CROWDSOURCED_REPORT_THRESHOLD) return null;
    const scamLikeCount = valid.filter((e) => SCAM_LIKE_REPORT_CATEGORIES.includes(e.category)).length;
    const ratio = valid.length > 0 ? scamLikeCount / valid.length : 0;
    if (ratio < CROWDSOURCED_SCAM_RATIO) return null;

    return {
      reportCount: valid.length,
      scamLikeCount,
      ratio,
      reason: `High Report Ratio (${scamLikeCount}/${valid.length})`,
    };
  };

  const reportNumber = (number: string, description: string, category: ReportCategory) => {
    if (!currentUser?.email) {
      setLookupResult((prev) => prev ? { ...prev, msg: 'Please login to submit reports' } : prev);
      return;
    }

    const normalizedNumber = normalizePhoneNumber(number);
    let targetEntry = threatIntelDB.find((e) => e.number === normalizedNumber);
    if (!targetEntry) {
      // If user reports before the number exists in DB, create a default safe entry.
      const carrier = detectCarrier(normalizedNumber);
      const created: ThreatIntelEntry = {
        number: normalizedNumber,
        status: 'safe',
        riskScore: 0,
        carrier,
        source: 'User Discovery',
        reportCount: 0,
        totalLookups: 0,
        lastUpdated: new Date().toISOString(),
      };
      const updatedDB = [...threatIntelDB, created];
      updateDatabase(updatedDB);
      targetEntry = created;
    }
    const companyEntry = getCompanyByNumber(normalizedNumber);

    const normalizedReporter = normalizeEmail(currentUser.email);
    const now = Date.now();
    const reporterEventsLastDay = reportEvents.filter(
      (e) => normalizeEmail(e.reporterEmail) === normalizedReporter &&
      now - new Date(e.createdAt).getTime() <= 24 * 60 * 60 * 1000
    );

    // Product behavior: each report action increments risk/report percentage by +10.
    // No per-day cap is enforced here.

    const evidenceGate = getReportEvidenceGate(targetEntry);
    const anomalyScore = getReporterAnomalyScore(normalizedReporter, normalizedNumber);
    const anomalyGate = anomalyScore >= 0.8 ? 0 : anomalyScore >= 0.5 ? 0.3 : 1;
    const consensusGate = getConsensusGate(normalizedNumber);
    const invalidated = anomalyGate === 0;
    const weightedImpact = 0;

    const { updatedEvents } = appendReportEvent({
      number: normalizedNumber,
      category,
      reporterEmail: normalizedReporter,
      reporterDeviceId: deviceId || 'unknown-device',
      reporterNetworkSignature: normalizedReporter.split('@')[1] || 'unknown',
      description: description.trim() ? description.trim() : undefined,
      evidenceGate,
      anomalyGate,
      consensusGate,
      weightedImpact,
      invalidated,
      reason: invalidated ? 'Suspicious reporting behavior' : undefined,
    });

    // New rule: every report increases admin scamPercentage by +10%.
    // If total reports reach 10 (100%), auto move to CRITICAL_BLOCK.
    const totalReportsAll = updatedEvents.filter((e) => e.number === normalizedNumber).length;
    if (!companyEntry && totalReportsAll >= 10) {
      forceGlobalBlock(normalizedNumber);
      addToGlobalBlacklist(normalizedNumber, 'community', `Critical: ${totalReportsAll} reports`);
    }

    // Every report strictly adds +10 risk from the current stored value.
    const currentEntry = threatIntelDB.find((entry) => entry.number === normalizedNumber) || targetEntry;
    const currentRisk = Math.max(0, Number(currentEntry?.riskScore || 0));
    const currentReportCount = Math.max(0, Number(currentEntry?.reportCount || 0));
    const nextRisk = Math.min(99, currentRisk + 10);
    const nextReportCount = currentReportCount + 1;

    const nextEntry: ThreatIntelEntry = {
      ...(currentEntry as ThreatIntelEntry),
      number: normalizedNumber,
      riskScore: nextRisk,
      reportCount: nextReportCount,
      totalLookups: Math.max(Number(currentEntry?.totalLookups || 0), nextReportCount),
      status: mapRiskToStatus(nextRisk, true),
      lastUpdated: new Date().toISOString(),
    };

    const updatedDB = threatIntelDB.some((entry) => entry.number === normalizedNumber)
      ? threatIntelDB.map((entry) => (entry.number === normalizedNumber ? nextEntry : entry))
      : [...threatIntelDB, nextEntry];
    updateDatabase(updatedDB);

    // Community-driven critical escalation:
    // 10+ reports and >=80% scam-like categories => global critical blacklist.
    if (!companyEntry) {
      const escalation = evaluateCrowdsourcedCriticality(number, updatedEvents);
      if (escalation) {
        forceGlobalBlock(number);
        addToGlobalBlacklist(number, 'community', escalation.reason);
        upsertCriticalThreat(
          {
            number,
            source: 'community',
            status: 'pending',
            reason: escalation.reason,
            reportCount: escalation.reportCount,
            scamLikeCount: escalation.scamLikeCount,
            ratio: escalation.ratio,
          },
          { notify: isAdminView || currentUser?.role === 'superadmin' }
        );
      }
    }

    if (lookupResult?.number === normalizedNumber) {
      const updatedEntry = updatedDB.find((e) => e.number === normalizedNumber);
      if (updatedEntry) {
        const enforced = getActiveCriticalThreat(normalizedNumber) ? forceGlobalBlock(normalizedNumber) : updatedDB;
        const enforcedEntry = enforced.find((e) => e.number === normalizedNumber) || updatedEntry;
        setLookupResult({
          ...lookupResult,
          risk: enforcedEntry.riskScore,
          msg: getActiveCriticalThreat(number)
            ? 'Auto-blacklisted by community consensus'
            : invalidated
            ? 'Report invalidated (suspicious behavior detected)'
            : companyEntry
              ? 'Company number report saved (risk unchanged)'
              : 'Report accepted (+10 risk)',
          reportCount: updatedEntry.reportCount,
        });
      }
    }

    appendUserActivity({
      action: 'report',
      details: invalidated
        ? `Report invalidated for ${normalizedNumber}`
        : companyEntry
          ? `Reported ${normalizedNumber} (${category.replaceAll('_', ' ')}) — ${description.trim() ? description.trim() : 'No description'} [trusted company, score locked]`
          : `Reported ${normalizedNumber} (${category.replaceAll('_', ' ')}) — ${description.trim() ? description.trim() : 'No description'}`,
      dangerLevel: updatedDB.find((e) => e.number === normalizedNumber)?.riskScore ?? targetEntry.riskScore,
    });
  };

  const blockNumber = (number: string) => {
    const normalized = normalizePhoneNumber(number);
    // User block is personal only; never mutate shared threatIntelDB/admin risk state.
    if (!userBlacklist.includes(normalized)) {
      const nextUserBlacklist = [normalized, ...userBlacklist];
      setUserBlacklist(nextUserBlacklist);
      saveUserBlacklist(nextUserBlacklist);
    }

    if (lookupResult?.number === normalized) {
      setLookupResult({
        ...lookupResult,
        msg: 'Blocked in your personal blacklist',
      });
      setProtocolIdentity('INVALID');
      setHeaderMismatch(true);
    }

    appendUserActivity({
      action: 'block',
      details: `Blocked number ${normalized}`,
      dangerLevel: lookupResult?.number === normalized ? Number(lookupResult.risk || 0) : 0,
    });
  };

  const handleLookup = () => {
    if (!lookupNumber) return;
    // Keep lookup in reputation area; do not bounce to demo/login views.
    setAppView('app');
    if (!canViewOperatorActivity) {
      setActiveTab('consumer');
    }
    setLookupState('searching');
    setTimeout(() => {
      // Normalize the input number first
      const normalizedNumber = normalizePhoneNumber(lookupNumber.trim());
      const companyEntry = getCompanyByNumber(normalizedNumber);
      const adminBlocked = isGloballyBlacklisted(normalizedNumber);
      const userBlocked = userBlacklist.includes(normalizedNumber);
      
      // Validate the normalized number
      if (!validatePhoneNumber(normalizedNumber)) {
        setLookupResult({
          risk: 100,
          msg: 'Malformed Signaling Data'
        });
        setProtocolIdentity('VERIFIED');
        setHeaderMismatch(false);
        setLookupState('done');
        return;
      }
      
      let entry = threatIntelDB.find(e => e.number === normalizedNumber);
      let isBrandNewEntry = false;
      
      // If number doesn't exist, create a default safe record.
      if (!entry) {
        const analysis = calculateAdvancedRiskScore(normalizedNumber);
        const newEntry: ThreatIntelEntry = {
          number: normalizedNumber,
          status: 'safe',
          riskScore: 0,
          carrier: analysis.carrier,
          source: companyEntry ? 'System' : 'User Discovery',
          reportCount: 0,
          totalLookups: 1,
          lastUpdated: new Date().toISOString()
        };
        
        // Add to database
        const updatedDB = [...threatIntelDB, newEntry];
        updateDatabase(updatedDB);
        entry = newEntry;
        isBrandNewEntry = true;
      } else {
        const nowIso = new Date().toISOString();
        const updatedEntry: ThreatIntelEntry = {
          ...entry,
          totalLookups: Number(entry.totalLookups || 0) + 1,
          lastUpdated: nowIso,
        };
        const updatedDB = threatIntelDB.map((e) => (e.number === normalizedNumber ? updatedEntry : e));
        updateDatabase(updatedDB);
        entry = updatedEntry;
      }

      if (adminBlocked) {
        const enforced = forceGlobalBlock(normalizedNumber);
        const enforcedEntry = enforced.find((e) => e.number === normalizedNumber);
        setLookupResult({
          risk: enforcedEntry?.riskScore ?? 100,
          msg: canViewOperatorActivity ? 'BLOCKED BY ADMIN' : '100% BLOCKED BY ADMIN',
          number: normalizedNumber,
          carrier: enforcedEntry?.carrier || entry?.carrier || detectCarrier(normalizedNumber),
          reportCount: enforcedEntry?.reportCount || entry?.reportCount || 0
        });
        appendUserActivity({
          action: 'lookup',
          details: `Checked ${normalizedNumber}: BLOCKED BY ADMIN`,
          dangerLevel: enforcedEntry?.riskScore ?? 100,
        });
        setProtocolIdentity('INVALID');
        setHeaderMismatch(true);
        setLookupState('done');
        return;
      }

      if (userBlocked) {
        setLookupResult({
          risk: entry?.riskScore ?? 0,
          msg: 'Blocked in your personal blacklist',
          number: normalizedNumber,
          carrier: entry?.carrier || detectCarrier(normalizedNumber),
          reportCount: entry?.reportCount || 0
        });
        appendUserActivity({
          action: 'lookup',
          details: `Checked ${normalizedNumber}: BLOCKED (personal blacklist)`,
          dangerLevel: entry?.riskScore ?? 0,
        });
        setProtocolIdentity('INVALID');
        setHeaderMismatch(true);
        setLookupState('done');
        return;
      }

      const activeCritical = getActiveCriticalThreat(normalizedNumber);
      if (activeCritical && !companyEntry) {
        const enforced = forceGlobalBlock(normalizedNumber);
        const enforcedEntry = enforced.find((e) => e.number === normalizedNumber) || entry;
        setLookupResult({
          risk: enforcedEntry?.riskScore ?? 100,
          msg: `Global Critical Blacklist - ${activeCritical.reason}`,
          number: enforcedEntry.number,
          carrier: enforcedEntry.carrier,
          reportCount: enforcedEntry.reportCount
        });
        appendUserActivity({
          action: 'lookup',
          details: `Checked ${entry.number}: Global Critical Blacklist`,
          dangerLevel: enforcedEntry?.riskScore ?? 100,
        });
        setProtocolIdentity('INVALID');
        setHeaderMismatch(true);
        setLookupState('done');
        return;
      }
      
      // Brand-new local numbers start at 0% until we have supporting evidence.
      // Brand-new international numbers are immediately suspicious.
      if (isBrandNewEntry) {
        if (companyEntry) {
          setLookupResult({
            risk: 0,
            msg: `Verified Company Number${companyEntry.name ? ` - ${companyEntry.name}` : ''}`,
            number: entry.number,
            carrier: entry.carrier,
            reportCount: entry.reportCount
          });

          appendUserActivity({
            action: 'lookup',
            details: `Checked ${entry.number}: Verified Company Number`,
            dangerLevel: 0,
          });

          setProtocolIdentity('VERIFIED');
          setHeaderMismatch(false);
          setLookupState('done');
          return;
        }

        if (entry.carrier === 'International') {
          const internationalRisk = Math.max(60, entry.riskScore || 75);
          setLookupResult({
            risk: internationalRisk,
            msg: 'Medium Risk - Foreign Number (Suspicious)',
            number: entry.number,
            carrier: entry.carrier,
            reportCount: entry.reportCount
          });

          appendUserActivity({
            action: 'lookup',
            details: `Checked ${entry.number}: Medium Risk - Foreign Number (Suspicious)`,
            dangerLevel: internationalRisk,
          });

          setProtocolIdentity('VERIFIED');
          setHeaderMismatch(false);
          setLookupState('done');
          return;
        }

        setLookupResult({
          risk: 0,
          msg: 'New number - no risk data yet',
          number: entry.number,
          carrier: entry.carrier,
          reportCount: entry.reportCount
        });

        appendUserActivity({
          action: 'lookup',
          details: `Checked ${entry.number}: New number - no risk data yet`,
          dangerLevel: 0,
        });

        setProtocolIdentity('VERIFIED');
        setHeaderMismatch(false);
        setLookupState('done');
        return;
      }

      // Single source of truth: always use stored DB risk directly.
      // This guarantees each report visibly increases risk by exactly +10.
      let finalRisk = Math.max(0, Math.min(100, Number(entry.riskScore || 0)));

      // Now process the entry (whether existing or newly added)
      let msg = '';
      let identityStatus = 'VERIFIED';
      let hasHeaderMismatch = false;
      
      const finalStatus = mapRiskToStatus(finalRisk, true);
      switch (finalStatus) {
        case 'scam':
          msg = 'High Risk - Confirmed Scam';
          identityStatus = 'INVALID';
          hasHeaderMismatch = true;
          break;
        case 'spam':
          msg = 'High Risk - Spam Activity';
          identityStatus = 'INVALID';
          hasHeaderMismatch = true;
          break;
        case 'suspicious':
          msg = 'Medium Risk - Suspicious Activity';
          identityStatus = 'VERIFIED';
          hasHeaderMismatch = false;
          break;
        case 'safe':
          msg = 'Verified Safe Node';
          identityStatus = 'VERIFIED';
          hasHeaderMismatch = false;
          break;
        default:
          msg = 'Status Unknown';
          identityStatus = 'VERIFIED';
          hasHeaderMismatch = false;
      }
      if (companyEntry) {
        msg = `Verified Company Number${companyEntry.name ? ` - ${companyEntry.name}` : ''}`;
        identityStatus = 'VERIFIED';
        hasHeaderMismatch = false;
      }
      
      setLookupResult({
        risk: finalRisk,
        msg,
        number: entry.number,
        carrier: entry.carrier,
        reportCount: entry.reportCount
      });

      appendUserActivity({
        action: 'lookup',
        details: `Checked ${entry.number}: ${msg}`,
        dangerLevel: finalRisk,
      });
      
      setProtocolIdentity(identityStatus);
      setHeaderMismatch(hasHeaderMismatch);
      setLookupState('done');
    }, 1500);
  };

  const filteredUserActivity = userActivity.filter(
    entry => entry.userEmail === normalizeEmail(currentUser?.email || '')
  );

  const activityWithDangerFallback = filteredUserActivity.map((entry) => {
    if (entry.dangerLevel && entry.dangerLevel > 0) return entry;

    const numberMatch = entry.details.match(/\+994\d{9}/);
    if (!numberMatch) return entry;
    const dbEntry = threatIntelDB.find((t) => t.number === numberMatch[0]);
    if (!dbEntry) return entry;

    return { ...entry, dangerLevel: dbEntry.riskScore };
  });

  const activityByType = activityWithDangerFallback.filter((entry) => {
    if (activityFilter === 'all') return true;
    if (activityFilter === 'blocked') return entry.action === 'block';
    if (activityFilter === 'reported') return entry.action === 'report';
    if (activityFilter === 'lookups') return entry.action === 'lookup';
    if (activityFilter === 'calls') return entry.action === 'call';
    return true;
  });

  const sortedUserActivity = [...activityByType].sort((a, b) => {
    if (activitySort === 'danger') {
      return (b.dangerLevel || 0) - (a.dangerLevel || 0);
    }
    return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
  });

  const getDangerTextClass = (dangerLevel: number) => {
    if (dangerLevel >= 80) return 'text-red-400';
    if (dangerLevel >= 60) return 'text-orange-400';
    if (dangerLevel >= 30) return 'text-yellow-400';
    return 'text-emerald-400';
  };

  const confirmGlobalBlockFromReportCenter = (number: string) => {
    const row = reportCenterRows.find((r) => r.number === number);
    const reason = row && row.totalReports > 0
      ? `High Report Ratio (${row.scamLikeCount}/${row.totalReports})`
      : 'Admin global block';
    forceGlobalBlock(number);
    addToGlobalBlacklist(normalizePhoneNumber(number), 'admin', reason);
    setAdminToastMessage(`Number ${number} moved to Global Critical Blacklist.`);
  };

  const whitelistFromAdmin = (number: string) => {
    const nowIso = new Date().toISOString();
    const nextBlacklist = globalBlacklist.filter((e) => e.number !== number);
    setGlobalBlacklist(nextBlacklist);
    saveGlobalBlacklist(nextBlacklist);

    const nextThreats = criticalThreats.map((t) =>
      t.number === number ? { ...t, status: 'whitelisted' as const, updatedAt: nowIso } : t
    );
    setCriticalThreatAndPersist(nextThreats);

    const updatedDB = threatIntelDB.map((entry) =>
      entry.number === number
        ? {
            ...entry,
            status: 'safe' as const,
            riskScore: 0,
            source: 'System' as const,
            lastUpdated: nowIso,
          }
        : entry
    );
    updateDatabase(updatedDB);
  };

  const parseReportActivityDetails = (rawDetails: string) => {
    const details = rawDetails
      .replace(/\s*\(trust\s+\d+(\.\d+)?%\)\s*/gi, ' ')
      .replace(/\s{2,}/g, ' ')
      .trim();

    const match = details.match(/^Reported\s+(?<number>\+\d+)\s+\((?<cat>[^)]+)\)\s+—\s*(?<desc>.*)$/i);
    if (!match?.groups) return { details };

    const number = match.groups.number;
    const catLabelRaw = match.groups.cat.trim().toLowerCase();
    const userDesc = (match.groups.desc || '').trim();

    const categoryKey: ReportCategory | null =
      catLabelRaw === 'app fraud'
        ? 'app_fraud'
        : catLabelRaw === 'vishing'
          ? 'vishing'
          : catLabelRaw === 'caller id spoofing' || catLabelRaw === 'caller-id spoofing'
            ? 'caller_id_spoofing'
            : catLabelRaw === 'spam'
              ? 'spam'
              : catLabelRaw === 'other'
                ? 'other'
                : null;

    return { details, number, categoryKey, userDesc };
  };

  return (
    <div className="min-h-screen bg-[#030712] text-slate-200 selection:bg-blue-500/30">
      {appView === 'app' && (
        <nav className="fixed top-0 left-0 right-0 z-50 h-16 bg-black/20 backdrop-blur-md border-b border-white/10 px-8 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-cyan-500 rounded-sm flex items-center justify-center text-black">
              <Phone className="w-4 h-4" />
            </div>
            <span className="font-display font-bold text-xl tracking-tight uppercase text-cyan-400">
            TrustCall
            </span>
          </div>
          
          <div className="hidden md:flex items-center bg-white/5 border border-white/10 p-1 rounded-xl">
            {[
              { id: 'demo', label: 'Live Demo', icon: Zap },
              ...(canViewPersonalDashboard ? [{ id: 'consumer', label: 'Personal Dashboard', icon: ShieldCheck }] : []),
              ...(canViewOperatorActivity ? [{ id: 'operator', label: 'Activity', icon: Activity }] : []),
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-2 px-4 py-1.5 rounded-lg text-[11px] uppercase tracking-widest font-bold transition-all ${
                  activeTab === tab.id 
                    ? 'bg-cyan-500 text-black shadow-lg shadow-cyan-500/20' 
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-4">
            {currentUser && (
              <div className="hidden md:flex flex-col items-end mr-2">
                <span className="text-[10px] text-slate-500 uppercase font-bold tracking-widest">Logged in</span>
                <span className="text-[10px] text-slate-300 font-mono">{currentUser.email}</span>
              </div>
            )}
            <button
              onClick={handleLogout}
              className="px-4 py-2 rounded-xl bg-slate-900 border border-white/10 text-slate-300 hover:text-white hover:border-cyan-500/40 transition-colors text-[10px] font-bold uppercase tracking-widest"
            >
              Logout
            </button>
          </div>
        </nav>
      )}

      {/* Main Content Area */}
      <main className={`${appView === 'app' ? 'pt-24 pb-12' : 'pt-20 pb-12'} px-6 max-w-7xl mx-auto`}>
        {appView !== 'app' && (
          <div className="min-h-[70vh] flex items-center justify-center">
            <div className="w-full max-w-md rounded-3xl border border-cyan-500/20 bg-[#06131f] p-8 shadow-2xl shadow-cyan-500/10">
              <div className="mb-6">
                <div className="text-sm font-semibold uppercase tracking-[0.3em] text-cyan-300">Access</div>
                <h2 className="mt-2 text-2xl font-bold text-white">
                  {appView === 'login' ? 'Login' : 'Registration'}
                </h2>
              </div>

              {appView === 'login' ? (
                <div className="space-y-4">
                  <div>
                    <label className="mb-2 block text-xs uppercase tracking-[0.3em] text-slate-500">Email</label>
                    <input
                      type="email"
                      value={loginEmail}
                      onChange={(e) => setLoginEmail(e.target.value)}
                      placeholder="user@example.com"
                      className="w-full rounded-2xl border border-slate-700 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-500/60"
                    />
                  </div>
                  <div>
                    <label className="mb-2 block text-xs uppercase tracking-[0.3em] text-slate-500">Password</label>
                    <input
                      type="password"
                      value={loginPassword}
                      onChange={(e) => setLoginPassword(e.target.value)}
                      placeholder="Password"
                      className="w-full rounded-2xl border border-slate-700 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-500/60"
                    />
                  </div>

                  {loginMessage && (
                    <div className={`rounded-2xl px-4 py-3 text-sm ${
                      loginMessage.type === 'success'
                        ? 'bg-emerald-500/10 text-emerald-200 border border-emerald-500/20'
                        : 'bg-red-500/10 text-red-200 border border-red-500/20'
                    }`}>
                      {loginMessage.text}
                    </div>
                  )}

                  <div className="flex flex-col gap-3">
                    <button
                      onClick={handlePrimaryLogin}
                      className="rounded-2xl bg-cyan-500 px-5 py-3 text-sm font-bold uppercase tracking-[0.2em] text-black transition hover:bg-cyan-400"
                    >
                      Login
                    </button>
                    <button
                      onClick={() => { setAppView('register'); setRegMessage(null); }}
                      className="rounded-2xl border border-slate-700 bg-slate-950/80 px-5 py-3 text-sm font-bold uppercase tracking-[0.2em] text-slate-300 transition hover:border-slate-500 hover:text-white"
                    >
                      I don&apos;t have an account
                    </button>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div>
                    <label className="mb-2 block text-xs uppercase tracking-[0.3em] text-slate-500">Full name</label>
                    <input
                      value={regName}
                      onChange={(e) => setRegName(e.target.value)}
                      placeholder="Name"
                      className="w-full rounded-2xl border border-slate-700 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-500/60"
                    />
                  </div>
                  <div>
                    <label className="mb-2 block text-xs uppercase tracking-[0.3em] text-slate-500">Email</label>
                    <input
                      type="email"
                      value={regEmail}
                      onChange={(e) => setRegEmail(e.target.value)}
                      placeholder="name@example.com"
                      className="w-full rounded-2xl border border-slate-700 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-500/60"
                    />
                  </div>
                  <div>
                    <label className="mb-2 block text-xs uppercase tracking-[0.3em] text-slate-500">Password</label>
                    <input
                      type="password"
                      value={regPassword}
                      onChange={(e) => setRegPassword(e.target.value)}
                      placeholder="Password"
                      className="w-full rounded-2xl border border-slate-700 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-500/60"
                    />
                  </div>

                  {regMessage && (
                    <div className={`rounded-2xl px-4 py-3 text-sm ${
                      regMessage.type === 'success'
                        ? 'bg-emerald-500/10 text-emerald-200 border border-emerald-500/20'
                        : 'bg-red-500/10 text-red-200 border border-red-500/20'
                    }`}>
                      {regMessage.text}
                    </div>
                  )}

                  <div className="flex flex-col gap-3">
                    <button
                      onClick={handleRegisterSubmit}
                      className="rounded-2xl bg-cyan-500 px-5 py-3 text-sm font-bold uppercase tracking-[0.2em] text-black transition hover:bg-cyan-400"
                    >
                      Register
                    </button>
                    <button
                      onClick={() => { setAppView('login'); setRegMessage(null); }}
                      className="rounded-2xl border border-slate-700 bg-slate-950/80 px-5 py-3 text-sm font-bold uppercase tracking-[0.2em] text-slate-300 transition hover:border-slate-500 hover:text-white"
                    >
                      Back to login
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {appView === 'app' && (
          <AnimatePresence mode="wait">
          {activeTab === 'demo' && (
            <motion.div
              key="demo"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="grid lg:grid-cols-2 gap-8"
            >
              <div className="space-y-6">
                <div className="glass-panel p-8">
                  <h2 className="font-display text-3xl font-bold mb-4">Telecom Hackathon Demo</h2>
                  <p className="text-slate-400 mb-8 max-w-md">
                    Experience the network-level defense of TrustCall. We analyze SIP signaling, STIR/SHAKEN headers, and behavioral patterns before the user's phone even vibrates.
                  </p>
                  
                  <div className="grid grid-cols-3 gap-4">
                    <button 
                      onClick={() => startDemo('safe')}
                      className="group flex flex-col items-center gap-3 p-6 rounded-xl bg-slate-800 border border-white/10 hover:bg-slate-700 transition-all text-center"
                    >
                      <div className="w-12 h-12 rounded-full bg-cyan-500/20 flex items-center justify-center group-hover:scale-110 transition-transform">
                        <CheckCircle2 className="text-cyan-400" />
                      </div>
                      <div>
                        <div className="font-bold text-[10px] uppercase tracking-widest text-cyan-400">Simulate Safe</div>
                        <div className="text-[10px] text-slate-500 mt-1">Verified STIR/SHAKEN</div>
                      </div>
                    </button>

                    <button 
                      onClick={() => startDemo('spam')}
                      className="group flex flex-col items-center gap-3 p-6 rounded-xl bg-orange-600 border border-white/10 hover:bg-orange-500 transition-all text-center shadow-lg shadow-orange-900/50"
                    >
                      <div className="w-12 h-12 rounded-full bg-white/20 flex items-center justify-center group-hover:scale-110 transition-transform">
                        <PhoneOff className="text-white" />
                      </div>
                      <div>
                        <div className="font-bold text-[10px] uppercase tracking-widest text-white">Simulate Spam</div>
                        <div className="text-[10px] text-orange-200/50 mt-1">Marketing Pattern</div>
                      </div>
                    </button>

                    <button 
                      onClick={() => startDemo('scam')}
                      className="group flex flex-col items-center gap-3 p-6 rounded-xl bg-red-600 border border-white/10 hover:bg-red-500 transition-all text-center shadow-lg shadow-red-900/50"
                    >
                      <div className="w-12 h-12 rounded-full bg-white/20 flex items-center justify-center group-hover:scale-110 transition-transform">
                        <ShieldAlert className="text-white" />
                      </div>
                      <div>
                        <div className="font-bold text-[10px] uppercase tracking-widest text-white">Simulate Attack</div>
                        <div className="text-[10px] text-red-200/50 mt-1">International Spoofing</div>
                      </div>
                    </button>
                  </div>
                </div>

                <div className="glass-panel p-6">
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="font-bold flex items-center gap-2">
                      <Database className="w-4 h-4 text-cyan-400" />
                      Protocol Analysis (Live)
                    </h3>
                    <span className="text-[10px] bg-cyan-500/20 text-cyan-400 px-2 py-1 rounded-full border border-cyan-500/30">
                      SIP:STIR:SHAKEN
                    </span>
                  </div>
                  <div className="space-y-4 font-mono text-xs">
                    <div className="p-3 bg-black/40 rounded-lg border border-white/5 space-y-1">
                      <div className="text-slate-500 italic">// Signaling Metadata</div>
                      <div className="flex justify-between">
                        <span className="text-cyan-400">P-Asserted-Identity:</span>
                        <span className="text-slate-300">"{currentCall?.callerName || 'Unknown Caller'}" &lt;sip:{currentCall?.callerNumber?.replace('+', '')}@telco.com&gt;</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-cyan-400">User-Agent:</span>
                        <span className="text-slate-300">{currentCall?.metadata?.userAgent || 'Unknown'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-cyan-400">Identity:</span>
                        <span className={`text-cyan-500 ${currentCall?.riskLevel === 'dangerous' ? 'text-red-500' : currentCall?.riskLevel === 'suspicious' ? 'text-orange-500' : 'text-cyan-500'}`}>
                          eyJhbGciOiJFUzI1NiIs... [{currentCall?.metadata?.isStirShakenVerified ? 'VERIFIED' : 'INVALID'}]
                        </span>
                      </div>
                      {currentScenario && (
                        <div className="flex justify-between">
                          <span className="text-cyan-400">Scenario:</span>
                          <span className="text-slate-300">{currentScenario.metadata}</span>
                        </div>
                      )}
                      <div className="flex justify-between">
                        <span className="text-cyan-400">Verification Level:</span>
                        <span className={`font-bold ${
                          lookupResult?.risk === 0 ? 'text-emerald-400' :
                          lookupResult?.risk && lookupResult.risk <= 30 ? 'text-yellow-400' :
                          lookupResult?.risk && lookupResult.risk <= 70 ? 'text-orange-400' : 'text-red-400'
                        }`}>
                          {lookupResult?.risk === 0 ? 'A (Full)' :
                           lookupResult?.risk && lookupResult.risk <= 30 ? 'B (Partial)' :
                           lookupResult?.risk && lookupResult.risk <= 70 ? 'C (Gateway)' : 'D (None)'}
                        </span>
                      </div>
                      {headerMismatch && (
                        <div className="flex justify-between">
                          <span className="text-red-400">Header Mismatch:</span>
                          <span className="text-red-500">DETECTED</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              <div className="relative flex items-center justify-center min-h-[600px]">
                <AnimatePresence>
                  {isIncomingCall && currentCall && (
                    <motion.div
                      initial={{ scale: 0.9, opacity: 0 }}
                      animate={{ scale: 1, opacity: 1 }}
                      exit={{ scale: 0.9, opacity: 0 }}
                      className="absolute inset-0 flex items-center justify-center z-10"
                    >
                      <IncomingCallOverlay 
                        call={currentCall} 
                        onClose={() => setIsIncomingCall(false)} 
                      />
                    </motion.div>
                  )}
                </AnimatePresence>
                
                {!isIncomingCall && (
                  <div className="text-center space-y-4 text-slate-500">
                    <div className="w-20 h-20 bg-slate-900 border border-white/5 rounded-full flex items-center justify-center mx-auto animate-pulse">
                      <Phone className="w-8 h-8" />
                    </div>
                    <p className="text-sm">Awaiting incoming network signals...</p>
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {activeTab === 'consumer' && (
            <motion.div
              key="consumer"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="space-y-8"
            >
              {/* Number Lookup Section */}
              <div className="glass-panel p-8 overflow-hidden relative group">
                <div className="absolute top-0 right-0 p-4 opacity-10">
                  <Database className="w-24 h-24 text-cyan-400" />
                </div>
                <div className="relative z-10 max-w-xl">
                  <h3 className="text-lg font-bold mb-2 flex items-center gap-2 text-white font-display">
                    <Radio className="w-5 h-5 text-cyan-400" />
                    Manual Network Inquiry
                  </h3>
                  <p className="text-sm text-slate-400 mb-6 font-medium">Verify any number against the Global Threat Intelligence Layer before you call back.</p>
                  
                  <div className="flex flex-col sm:flex-row gap-3">
                    <div className="flex-1 relative">
                      <Phone className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                      <input 
                        type="text" 
                        value={lookupNumber}
                        onChange={(e) => setLookupNumber(e.target.value)}
                        placeholder="+994 -- --- -- --"
                        className="w-full pl-11 pr-4 py-3.5 bg-black/40 border border-white/10 rounded-xl outline-none focus:border-cyan-500/50 transition-colors text-white font-mono"
                      />
                    </div>
                    <button 
                      type="button"
                      onClick={handleLookup}
                      disabled={lookupState === 'searching'}
                      className="px-8 py-3.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-black font-bold rounded-xl transition-all shadow-lg shadow-cyan-900/20 uppercase text-xs tracking-widest whitespace-nowrap"
                    >
                      {lookupState === 'searching' ? 'Inquiring...' : 'Check Reputation'}
                    </button>
                  </div>

                  <AnimatePresence>
                    {lookupState === 'done' && lookupResult && (
                      <motion.div 
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        className="mt-6 pt-6 border-t border-white/5"
                      >
                        {(() => {
                          const displayRisk = Number.isFinite(lookupResult.risk)
                            ? Math.round(lookupResult.risk * 10) / 10
                            : 0;
                          const riskBucket = displayRisk >= 50 ? 'danger' : displayRisk >= 1 ? 'caution' : 'secure';

                          const containerClass =
                            riskBucket === 'danger'
                              ? 'bg-red-500/10 border-red-500/20'
                              : riskBucket === 'caution'
                                ? 'bg-yellow-500/10 border-yellow-500/20'
                                : 'bg-emerald-500/10 border-emerald-500/20';

                          const badgeClass =
                            riskBucket === 'danger'
                              ? 'bg-red-500/20 text-red-500'
                              : riskBucket === 'caution'
                                ? 'bg-yellow-500/20 text-yellow-500'
                                : 'bg-emerald-500/20 text-emerald-400';

                          const labelClass =
                            riskBucket === 'danger'
                              ? 'text-red-400'
                              : riskBucket === 'caution'
                                ? 'text-yellow-400'
                                : 'text-emerald-400';

                          const labelText =
                            riskBucket === 'danger' ? 'Danger' : riskBucket === 'caution' ? 'Caution' : 'Secure';

                          return (
                        <div className={`p-4 rounded-xl border flex items-center gap-4 ${
                          containerClass
                        }`}>
                          <div className={`w-12 h-12 rounded-full flex items-center justify-center shrink-0 ${
                            badgeClass
                          }`}>
                            <span className="text-sm font-bold">{displayRisk.toFixed(1)}%</span>
                          </div>
                          <div className="flex-1">
                            <div className={`text-xs font-bold uppercase tracking-wider mb-0.5 ${
                              labelClass
                            }`}>
                              {labelText}
                            </div>
                            <div className="text-[11px] text-slate-400 font-medium">{lookupResult.msg}</div>
                            {lookupResult.carrier && (
                              <div className="text-[10px] text-slate-500 mt-1">
                                Carrier: {lookupResult.carrier} • Reports: {lookupResult.reportCount || 0}
                              </div>
                            )}
                          </div>
                          {lookupResult.number && (
                            <div className={`flex items-center gap-2 ${hasReportedNumberToday(lookupResult.number!) ? 'w-40' : ''}`}>
                              {!hasReportedNumberToday(lookupResult.number!) && (
                                <button
                                  type="button"
                                  onClick={() => {
                                    if (!isReportComposerOpen) {
                                      setIsReportComposerOpen(true);
                                      setReportDraftDescription('');
                                      setReportDraftCategory('');
                                      return;
                                    }
                                    if (!reportDraftCategory) return;
                                    reportNumber(lookupResult.number!, reportDraftDescription, reportDraftCategory);
                                    setIsReportComposerOpen(false);
                                    setReportDraftDescription('');
                                    setReportDraftCategory('');
                                  }}
                                  className={`px-3 py-1.5 text-xs font-bold uppercase rounded border transition-colors ${
                                    isReportComposerOpen && !reportDraftCategory
                                      ? 'bg-slate-500/10 text-slate-500 border-white/10 cursor-not-allowed'
                                      : 'bg-red-500/20 hover:bg-red-500/30 text-red-400 border-red-500/30'
                                  }`}
                                >
                                  {isReportComposerOpen ? 'Submit report' : 'Report'}
                                </button>
                              )}
                              <button
                                type="button"
                                onClick={() => blockNumber(lookupResult.number!)}
                                className={`px-3 py-1.5 rounded-lg border border-red-500/30 bg-red-500/20 text-red-200 text-xs font-bold uppercase tracking-widest transition hover:bg-red-500/30 hover:text-white active:bg-red-500/40 focus:outline-none focus:ring-2 focus:ring-red-500/30 ${
                                  hasReportedNumberToday(lookupResult.number!) ? 'w-full text-center' : ''
                                }`}
                              >
                                Block
                              </button>
                            </div>
                          )}
                        </div>
                          );
                        })()}
                        {isReportComposerOpen && (
                          <div className="mt-3 w-full">
                            <label className="mb-2 block text-[10px] font-bold uppercase tracking-widest text-slate-500">
                              Report type
                            </label>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                              {(
                                [
                                  { id: 'app_fraud', label: 'APP fraud' },
                                  { id: 'vishing', label: 'Vishing' },
                                  { id: 'caller_id_spoofing', label: 'Caller ID spoofing' },
                                  { id: 'spam', label: 'Spam' },
                                  { id: 'other', label: 'Other' },
                                ] as const
                              ).map((opt) => (
                                <button
                                  key={opt.id}
                                  type="button"
                                  onClick={() => setReportDraftCategory(opt.id)}
                                  className={`flex items-center justify-between gap-3 rounded-xl border px-3 py-2 text-left transition ${
                                    reportDraftCategory === opt.id
                                      ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-200'
                                      : 'border-white/10 bg-black/30 text-slate-300 hover:bg-white/5'
                                  }`}
                                >
                                  <span className="text-[11px] font-bold uppercase tracking-widest">{opt.label}</span>
                                  <span
                                    className={`h-3 w-3 rounded-full border ${
                                      reportDraftCategory === opt.id ? 'border-cyan-400 bg-cyan-400' : 'border-slate-600'
                                    }`}
                                  />
                                </button>
                              ))}
                            </div>
                            {!reportDraftCategory && (
                              <div className="mt-2 text-[10px] text-slate-500 uppercase tracking-widest font-bold">
                                Choose one option to submit
                              </div>
                            )}
                            <label className="mb-2 block text-[10px] font-bold uppercase tracking-widest text-slate-500">
                              Report description
                            </label>
                            <textarea
                              value={reportDraftDescription}
                              onChange={(e) => setReportDraftDescription(e.target.value)}
                              placeholder="Why are you reporting this number?"
                              className="w-full resize-none rounded-xl border border-white/10 bg-black/30 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500/40"
                              rows={3}
                            />
                            <div className="mt-2 flex justify-end">
                              <button
                                type="button"
                                onClick={() => { setIsReportComposerOpen(false); setReportDraftDescription(''); setReportDraftCategory(''); }}
                                className="px-3 py-1.5 rounded-lg border border-white/10 bg-white/5 text-[10px] font-bold uppercase tracking-widest text-slate-300 hover:bg-white/10"
                              >
                                Cancel
                              </button>
                            </div>
                          </div>
                        )}
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              </div>

              <div className="glass-panel p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-bold flex items-center gap-2">
                    <Activity className="w-4 h-4 text-cyan-400" />
                    Activity
                  </h3>
                  <span className="text-[10px] text-slate-500 uppercase tracking-widest">
                    Total: {filteredUserActivity.length}
                  </span>
                </div>

                <div className="mb-4 flex flex-wrap gap-2">
                  <button
                    onClick={() => setActivityFilter('all')}
                    className={`px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-widest border transition-colors ${
                      activityFilter === 'all'
                        ? 'bg-slate-500/20 border-slate-400/40 text-slate-200'
                        : 'bg-white/5 border-white/10 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    All
                  </button>
                  <button
                    onClick={() => setActivityFilter('lookups')}
                    className={`px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-widest border transition-colors ${
                      activityFilter === 'lookups'
                        ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300'
                        : 'bg-white/5 border-white/10 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Lookups
                  </button>
                  <button
                    onClick={() => setActivityFilter('calls')}
                    className={`px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-widest border transition-colors ${
                      activityFilter === 'calls'
                        ? 'bg-indigo-500/20 border-indigo-500/40 text-indigo-300'
                        : 'bg-white/5 border-white/10 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Calls
                  </button>
                  <button
                    onClick={() => setActivityFilter('reported')}
                    className={`px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-widest border transition-colors ${
                      activityFilter === 'reported'
                        ? 'bg-orange-500/20 border-orange-500/40 text-orange-300'
                        : 'bg-white/5 border-white/10 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Reported
                  </button>
                  <button
                    onClick={() => setActivityFilter('blocked')}
                    className={`px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-widest border transition-colors ${
                      activityFilter === 'blocked'
                        ? 'bg-red-500/20 border-red-500/40 text-red-300'
                        : 'bg-white/5 border-white/10 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Blocked
                  </button>
                  <button
                    onClick={() => setActivitySort('time')}
                    className={`px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-widest border transition-colors ${
                      activitySort === 'time'
                        ? 'bg-blue-500/20 border-blue-500/40 text-blue-300'
                        : 'bg-white/5 border-white/10 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Time
                  </button>
                  <button
                    onClick={() => setActivitySort('danger')}
                    className={`px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-widest border transition-colors ${
                      activitySort === 'danger'
                        ? 'bg-red-500/20 border-red-500/40 text-red-300'
                        : 'bg-white/5 border-white/10 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Danger level
                  </button>
                </div>

                <div className="space-y-3 max-h-72 overflow-auto pr-1">
                  {sortedUserActivity.length === 0 && (
                    <div className="text-sm text-slate-500">
                      No activity yet. Lookup/report/block actions will appear here.
                    </div>
                  )}

                  {sortedUserActivity.slice(0, 25).map((entry) => (
                    <div key={entry.id} className="rounded-xl border border-white/10 bg-white/5 p-3">
                      <div className="flex items-center justify-between gap-3">
                        <span className={`px-2 py-1 rounded-full text-[10px] font-bold uppercase border ${
                          entry.action === 'block'
                            ? 'bg-red-500/15 text-red-300 border-red-500/30'
                            : entry.action === 'report'
                              ? 'bg-orange-500/15 text-orange-300 border-orange-500/30'
                              : entry.action === 'call'
                                ? 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30'
                                : 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
                        }`}>
                          {entry.action}
                        </span>
                        <span className="text-[10px] text-slate-500">
                          {new Date(entry.createdAt).toLocaleString()}
                        </span>
                      </div>
                      {entry.action === 'report' ? (() => {
                        const parsed = parseReportActivityDetails(entry.details);
                        const meta = parsed.categoryKey ? REPORT_CATEGORY_META[parsed.categoryKey] : null;

                        // Fallback if details aren't in expected format
                        if (!parsed.number || !meta) {
                          return (
                            <div className="mt-2 text-sm text-slate-300">
                              {parsed.details ?? entry.details}
                            </div>
                          );
                        }

                        return (
                          <div className="mt-2">
                            <div className="flex items-start justify-between gap-3">
                              <div className="text-sm text-slate-300">
                                <span className="font-semibold">Reported</span>{' '}
                                <span className="font-mono">{parsed.number}</span>
                                {parsed.userDesc ? (
                                  <span className="text-slate-400">{' '}— {parsed.userDesc}</span>
                                ) : null}
                              </div>
                              <span className={`shrink-0 px-2 py-1 rounded-full text-[10px] font-bold uppercase border ${meta.badgeClass}`}>
                                {meta.label}
                              </span>
                            </div>
                            <div className="mt-1 text-[11px] text-slate-500">
                              {meta.description}
                            </div>
                          </div>
                        );
                      })() : (
                        <div className="mt-2 text-sm text-slate-300">
                          {entry.details.replace(/\s*\(trust\s+\d+(\.\d+)?%\)\s*/gi, ' ').replace(/\s{2,}/g, ' ').trim()}
                        </div>
                      )}
                      <div className="mt-1 text-[10px] text-slate-500">
                        Danger level:{' '}
                        <span className={`font-bold ${getDangerTextClass(entry.dangerLevel ?? 0)}`}>
                          {(entry.dangerLevel ?? 0).toFixed(1)}%
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {(isAdminView || currentUser?.role === 'superadmin') && (
                <div className="glass-panel p-6">
                  <h3 className="font-bold mb-4">Risk Exposure Over Time</h3>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={CHART_DATA}>
                        <defs>
                          <linearGradient id="colorCalls" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px' }}
                        />
                        <Area type="monotone" dataKey="blocked" stroke="#ef4444" fillOpacity={1} fill="url(#colorCalls)" />
                        <Area type="monotone" dataKey="calls" stroke="#3b82f6" fillOpacity={1} fill="url(#colorCalls)" />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}
            </motion.div>
          )}

          {activeTab === 'operator' && (
            <motion.div
              key="operator"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className={`space-y-6 ${isAdminView ? 'ring-1 ring-red-500/30 border border-red-500/10' : ''}`}
            >
              {trustGuardNotice && (isAdminView || currentUser?.role === 'superadmin') && (
                <div className="rounded-2xl border border-red-500/30 bg-gradient-to-r from-red-500/15 via-red-500/5 to-transparent px-4 py-3 flex items-center justify-between gap-3">
                  <div className="text-sm text-red-200">
                    <span className="font-bold uppercase tracking-widest text-[10px] text-red-300 mr-2">TrustCall Guard</span>
                    {trustGuardNotice}
                  </div>
                  <button
                    onClick={() => setTrustGuardNotice(null)}
                    className="px-3 py-1.5 text-[10px] font-bold uppercase tracking-widest rounded-lg border border-red-500/30 bg-red-500/10 text-red-200 hover:bg-red-500/20"
                  >
                    Dismiss
                  </button>
                </div>
              )}
              {adminToastMessage && (
                <div className="rounded-2xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 flex items-center justify-between gap-3">
                  <div className="text-sm text-emerald-200">{adminToastMessage}</div>
                  <button
                    onClick={() => setAdminToastMessage(null)}
                    className="px-3 py-1.5 text-[10px] font-bold uppercase tracking-widest rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/20"
                  >
                    Dismiss
                  </button>
                </div>
              )}

              <div className="glass-panel p-6">
                <h3 className="text-sm font-bold mb-3 flex items-center gap-2 text-white uppercase tracking-widest">
                  <Radio className="w-4 h-4 text-cyan-400" />
                  Check Reputation
                </h3>
                <div className="flex flex-col sm:flex-row gap-3">
                  <div className="flex-1 relative">
                    <Phone className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input
                      type="text"
                      value={lookupNumber}
                      onChange={(e) => setLookupNumber(e.target.value)}
                      placeholder="+994 -- --- -- --"
                      className="w-full pl-11 pr-4 py-3 bg-black/40 border border-white/10 rounded-xl outline-none focus:border-cyan-500/50 transition-colors text-white font-mono"
                    />
                  </div>
                  <button
                    type="button"
                    onClick={handleLookup}
                    disabled={lookupState === 'searching'}
                    className="px-8 py-3 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-black font-bold rounded-xl transition-all shadow-lg shadow-cyan-900/20 uppercase text-xs tracking-widest whitespace-nowrap"
                  >
                    {lookupState === 'searching' ? 'Inquiring...' : 'Check Reputation'}
                  </button>
                </div>

                {lookupState === 'done' && lookupResult && (
                  <div className="mt-4 rounded-xl border border-white/10 bg-black/25 p-4 flex flex-col sm:flex-row sm:items-center gap-3">
                    <div className="flex-1">
                      <div className="text-sm font-bold text-slate-100">
                        {lookupResult.number || lookupNumber}
                      </div>
                      <div className="text-xs text-slate-400 mt-1">{lookupResult.msg}</div>
                      <div className="text-[11px] text-slate-500 mt-1">
                        Carrier: {lookupResult.carrier || 'Unknown'} • Reports: {lookupResult.reportCount || 0}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {lookupResult.number && (
                        <button
                          type="button"
                          onClick={() => blockNumber(lookupResult.number!)}
                          className="px-3 py-1.5 rounded-lg border border-red-500/30 bg-red-500/20 text-red-200 text-xs font-bold uppercase tracking-widest transition hover:bg-red-500/30 hover:text-white"
                        >
                          Block
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>

              <div className="glass-panel p-6">
                <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
                  <h3 className="font-bold flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-cyan-400" />
                    Report Center
                  </h3>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-slate-500 uppercase tracking-widest">Filter by Category</span>
                    <select
                      value={reportCenterCategoryFilter}
                      onChange={(e) => setReportCenterCategoryFilter(e.target.value as any)}
                      className="rounded-lg border border-white/10 bg-black/30 px-3 py-1.5 text-[11px] text-slate-200 outline-none focus:border-cyan-500/40"
                    >
                      <option value="all">All</option>
                      <option value="bank">Bank</option>
                      <option value="delivery">Delivery</option>
                      <option value="personal">Personal</option>
                    </select>
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-white/10">
                        <th className="text-left py-2 px-2 text-[11px] uppercase tracking-widest text-slate-500">Phone Number</th>
                        <th className="text-left py-2 px-2 text-[11px] uppercase tracking-widest text-slate-500">Total Reports</th>
                        <th className="text-left py-2 px-2 text-[11px] uppercase tracking-widest text-slate-500">Risk</th>
                        <th className="text-left py-2 px-2 text-[11px] uppercase tracking-widest text-slate-500">Last Reported</th>
                        <th className="text-left py-2 px-2 text-[11px] uppercase tracking-widest text-slate-500">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {reportCenterRows.map((row) => (
                        <React.Fragment key={row.number}>
                          <tr className={`border-b border-white/5 ${row.criticalActionRequired ? 'bg-red-500/10' : 'hover:bg-white/5'}`}>
                            <td className="py-2 px-2 font-mono text-slate-300">{isAdminView ? row.number : maskPhoneNumber(row.number)}</td>
                            <td className="py-2 px-2 text-slate-200 font-bold">{row.totalReports}</td>
                            <td className="py-2 px-2">
                              <span className={`font-bold ${row.reportPercentage >= 80 ? 'text-red-400' : row.reportPercentage >= 50 ? 'text-orange-400' : row.reportPercentage >= 25 ? 'text-yellow-400' : 'text-emerald-400'}`}>
                                {row.reportPercentage.toFixed(1)}%
                              </span>
                            </td>
                            <td className="py-2 px-2 text-slate-400 text-xs">
                              {row.lastReportedAt ? new Date(row.lastReportedAt).toLocaleString() : '—'}
                            </td>
                            <td className="py-2 px-2">
                              <div className="flex flex-wrap items-center gap-2">
                                {row.criticalActionRequired && (
                                  <span className="px-2 py-1 rounded-full text-[10px] font-bold uppercase border border-red-500/30 bg-red-500/20 text-red-300">
                                    Critical Action Required
                                  </span>
                                )}
                                <button
                                  onClick={() => setExpandedReportCenterNumber(expandedReportCenterNumber === row.number ? null : row.number)}
                                  className="px-2 py-1 rounded-lg border border-white/10 bg-white/5 text-[10px] font-bold uppercase tracking-widest text-slate-300 hover:bg-white/10"
                                >
                                  Details
                                </button>
                                <button
                                  onClick={() => confirmGlobalBlockFromReportCenter(row.number)}
                                  disabled={isGloballyBlacklisted(row.number)}
                                  className="px-2 py-1 rounded-lg border border-red-500/30 bg-red-500/20 text-[10px] font-bold uppercase tracking-widest text-red-200 hover:bg-red-500/30 disabled:opacity-50 disabled:cursor-not-allowed"
                                >
                                  {isGloballyBlacklisted(row.number) ? 'Blocked' : 'Block Globally'}
                                </button>
                              </div>
                            </td>
                          </tr>
                          {expandedReportCenterNumber === row.number && (
                            <tr className="border-b border-white/5 bg-black/20">
                              <td colSpan={5} className="py-3 px-2">
                                <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">
                                  Comments ({row.comments.length})
                                </div>
                                {row.comments.length === 0 ? (
                                  <div className="text-sm text-slate-500">No comments available for this number.</div>
                                ) : (
                                  <div className="space-y-2">
                                    {row.comments.slice(0, 10).map((comment, idx) => (
                                      <div key={`${row.number}-comment-${idx}`} className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-300">
                                        {comment}
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Database Registry Overview */}
              <div className="glass-panel p-6">
                <h3 className="font-bold mb-6 flex items-center gap-2">
                  <Database className="w-5 h-5 text-cyan-400" />
                  Database Registry Overview
                </h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-white/10">
                        <th className="text-left py-3 px-2 font-bold text-slate-400 uppercase tracking-wider text-xs">Phone Number</th>
                        <th className="text-left py-3 px-2 font-bold text-slate-400 uppercase tracking-wider text-xs">Category</th>
                        <th className="text-left py-3 px-2 font-bold text-slate-400 uppercase tracking-wider text-xs">Reports Risk</th>
                        <th className="text-left py-3 px-2 font-bold text-slate-400 uppercase tracking-wider text-xs">Source</th>
                        <th className="text-left py-3 px-2 font-bold text-slate-400 uppercase tracking-wider text-xs">Admin Override</th>
                      </tr>
                    </thead>
                    <tbody>
                      {registryRowsSorted.map((entry, index) => {
                        const critical = criticalThreats.find((t) => t.number === entry.number && t.status !== 'whitelisted');
                        const getStatusColor = (status: string) => {
                          switch (status) {
                            case 'scam': return 'bg-red-500/20 text-red-400 border-red-500/30';
                            case 'spam': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
                            case 'suspicious': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
                            case 'safe': return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
                            default: return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
                          }
                        };
                        
                        const getRiskColor = (risk: number) => {
                          if (risk >= 85) return 'text-red-400';
                          if (risk >= 60) return 'text-orange-400';
                          if (risk >= 30) return 'text-yellow-400';
                          return 'text-emerald-400';
                        };

                        const getSourceColor = (source: string) => {
                          return source === 'System' ? 'bg-blue-500/20 text-blue-400 border-blue-500/30' : 'bg-purple-500/20 text-purple-400 border-purple-500/30';
                        };

                        return (
                          <tr key={index} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                            <td className="py-3 px-2 font-mono text-slate-300">{isAdminView ? entry.number : maskPhoneNumber(entry.number)}</td>
                            <td className="py-3 px-2">
                              <span className={`px-2 py-1 rounded-full text-xs font-bold uppercase border ${getStatusColor(entry.status)}`}>
                                {entry.status}
                              </span>
                            </td>
                            <td className="py-3 px-2">
                              <span className={`font-bold ${getRiskColor(getReportPercent(entry))}`}>
                                {getReportPercent(entry)}%
                              </span>
                            </td>
                            <td className="py-3 px-2">
                              <span className={`px-2 py-1 rounded-full text-xs font-bold uppercase border ${getSourceColor(entry.source)}`}>
                                {entry.source}
                              </span>
                            </td>
                            <td className="py-3 px-2">
                              <div className="flex items-center gap-2">
                                <button
                                  onClick={() => confirmGlobalBlockFromReportCenter(entry.number)}
                                  disabled={isGloballyBlacklisted(entry.number)}
                                  className="px-2 py-1 rounded-lg border border-red-500/30 bg-red-500/20 text-red-200 text-[10px] font-bold uppercase tracking-widest hover:bg-red-500/30 disabled:opacity-50 disabled:cursor-not-allowed"
                                >
                                  {isGloballyBlacklisted(entry.number) ? 'Blocked' : 'Confirm Global Block'}
                                </button>
                                <button
                                  onClick={() => whitelistFromAdmin(entry.number)}
                                  className="px-2 py-1 rounded-lg border border-emerald-500/30 bg-emerald-500/15 text-emerald-300 text-[10px] font-bold uppercase tracking-widest hover:bg-emerald-500/25"
                                >
                                  Whitelist
                                </button>
                              </div>
                              {critical && (
                                <div className="mt-1 text-[10px] text-slate-400">
                                  Reason: {critical.reason}
                                </div>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <div className="mt-4 text-xs text-slate-500 flex items-center justify-between">
                  <span>Total Entries: {registryRowsSorted.length}</span>
                  <div className="flex gap-4">
                    <span className="flex items-center gap-1">
                      <div className="w-2 h-2 rounded-full bg-red-500"></div>
                      Scam (85-99%)
                    </span>
                    <span className="flex items-center gap-1">
                      <div className="w-2 h-2 rounded-full bg-orange-500"></div>
                      Spam (60-84%)
                    </span>
                    <span className="flex items-center gap-1">
                      <div className="w-2 h-2 rounded-full bg-yellow-500"></div>
                      Suspicious (30-59%)
                    </span>
                    <span className="flex items-center gap-1">
                      <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
                      Safe (0-15%)
                    </span>
                  </div>
                </div>
              </div>

              <div className="glass-panel p-6">
                <h3 className="font-bold mb-6 flex items-center gap-2 text-red-300">
                  <ShieldX className="w-5 h-5 text-red-400" />
                  Global_Blacklist_Table
                </h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-white/10">
                        <th className="text-left py-3 px-2 font-bold text-slate-400 uppercase tracking-wider text-xs">Phone Number</th>
                        <th className="text-left py-3 px-2 font-bold text-slate-400 uppercase tracking-wider text-xs">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {globalBlacklist.length === 0 && (
                        <tr>
                          <td colSpan={2} className="py-4 px-2 text-sm text-slate-500">
                            No globally blocked numbers yet.
                          </td>
                        </tr>
                      )}
                      {globalBlacklist.map((entry) => (
                        <tr key={entry.id} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                          <td className="py-3 px-2 font-mono text-slate-300">{isAdminView ? entry.number : maskPhoneNumber(entry.number)}</td>
                          <td className="py-3 px-2">
                            <span className="px-3 py-1 rounded-lg border border-red-500/30 bg-red-500/15 text-red-300 text-xs font-bold uppercase tracking-widest animate-pulse shadow-[0_0_12px_rgba(239,68,68,0.35)]">
                              {entry.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </motion.div>
          )}

          </AnimatePresence>
        )}
      </main>

      <footer className="h-12 bg-black/40 border-t border-white/10 px-8 flex items-center justify-between text-[10px] tracking-widest text-slate-500 uppercase">
        <div>Node ID: DXB-721 // Azerbaijan Region</div>
        <div className="flex gap-8">
          <span>Rules Engine: 1.2ms latency</span>
          <span>ML Pipeline: Dynamic</span>
          <span className="text-cyan-500">© 2026 TrustCall Security Foundation</span>
        </div>
      </footer>

      {/* Background Decor */}
      <div className="fixed inset-0 -z-10 pointer-events-none opacity-20">
        <div className="absolute inset-0" style={{ backgroundImage: 'radial-gradient(#fff 1px, transparent 1px)', backgroundSize: '40px 40px' }}></div>
      </div>
    </div>
  );
}

function IncomingCallOverlay({ call, onClose }: { call: CallEvent, onClose: () => void }) {
  const [progress, setProgress] = useState(0);
  const [isAnalyzed, setIsAnalyzed] = useState(false);
  const isDangerous = call.riskLevel === 'dangerous';
  const isSpam = call.riskLevel === 'suspicious';
  const isSafe = call.riskLevel === 'safe';

  useEffect(() => {
    const timer = setInterval(() => {
      setProgress(prev => {
        if (prev >= 100) {
          clearInterval(timer);
          setIsAnalyzed(true);
          return 100;
        }
        return prev + 2;
      });
    }, 30);
    return () => clearInterval(timer);
  }, []);

  const getThemeColors = () => {
    if (isDangerous) return { primary: 'red', bg: 'bg-red-500/20', ring: 'ring-red-500/10', border: 'border-red-500', text: 'text-red-500' };
    if (isSpam) return { primary: 'orange', bg: 'bg-orange-500/20', ring: 'ring-orange-500/10', border: 'border-orange-500', text: 'text-orange-500' };
    return { primary: 'cyan', bg: 'bg-cyan-500/20', ring: 'ring-cyan-500/10', border: 'border-cyan-500', text: 'text-cyan-500' };
  };

  const theme = getThemeColors();

  return (
    <div className={`w-full max-w-sm bg-white/5 backdrop-blur-2xl border border-white/10 rounded-2xl overflow-hidden shadow-2xl relative ${
      isAnalyzed ? `ring-4 ${theme.ring} scale-105 ${isDangerous ? 'animate-pulse' : ''}` : ''
    } transition-all duration-500`}>
      
      {/* Background Grid Pattern */}
      <div className="absolute inset-0 z-0 opacity-10 pointer-events-none" style={{ backgroundImage: 'radial-gradient(#fff 1px, transparent 1px)', backgroundSize: '20px 20px' }}></div>

      <div className="relative z-10 p-8 flex flex-col items-center text-center">
        <div className="absolute top-4 right-4 flex gap-1">
          {[1,2,3].map(i => <div key={i} className={`w-1.5 h-1.5 rounded-full ${isAnalyzed ? theme.text : 'bg-cyan-500 animate-pulse'}`} />)}
        </div>

        <div className="mb-6 relative">
          <div className={`w-24 h-24 rounded-full flex items-center justify-center transition-all duration-1000 ${
            !isAnalyzed ? 'bg-white/5' : theme.bg + ` ring-8 ${theme.ring}`
          }`}>
            {!isAnalyzed ? (
              <PhoneIncoming className="w-12 h-12 text-cyan-400 animate-bounce" />
            ) : isDangerous ? (
              <ShieldAlert className="w-12 h-12 text-red-500" />
            ) : isSpam ? (
              <PhoneOff className="w-12 h-12 text-orange-500" />
            ) : (
              <ShieldCheck className="w-12 h-12 text-cyan-500" />
            )}
          </div>
          
          {!isAnalyzed && (
            <svg className="absolute inset-0 w-24 h-24 -rotate-90">
              <circle cx="48" cy="48" r="44" stroke="currentColor" strokeWidth="2" fill="transparent" className="text-white/10" />
              <circle
                cx="48" cy="48" r="44" stroke="currentColor" strokeWidth="2" fill="transparent"
                strokeDasharray={2 * Math.PI * 44}
                strokeDashoffset={2 * Math.PI * 44 * (1 - progress / 100)}
                className="text-cyan-500 transition-all duration-300"
              />
            </svg>
          )}
        </div>

        <div className="space-y-1 mb-8">
          <div className="mb-2 text-[10px] uppercase tracking-[0.3em] text-slate-400">Incoming Call Analysis</div>
          <h4 className="text-4xl font-light tracking-tighter text-white">
            {call.callerNumber}
          </h4>
          <p className="text-[10px] font-bold text-slate-500 mt-2 tracking-widest uppercase">
            {!isAnalyzed ? 'Decrypting SIP Packets...' : (
              isDangerous ? 'FORCE BLOCK' : 
              isSpam ? 'SCREENING ADVISED' : 
              'VERIFIED IDENTITY'
            )}
          </p>
        </div>

        {isAnalyzed && (
          <motion.div 
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="w-full space-y-6"
          >
            <div className="p-4 bg-black/40 rounded-xl border border-white/10 text-left">
              <div className="flex justify-between items-center mb-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Risk Score</span>
                <span className={`text-xl font-bold font-display ${theme.text}`}>
                  {call.riskScore}%
                </span>
              </div>
              <div className="h-1 w-full bg-white/10 rounded-full overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all duration-1000 ${theme.text}`}
                  style={{ width: `${call.riskScore}%` }}
                />
              </div>
              
              <div className="mt-4 space-y-3">
                {call.factors.map((f, i) => (
                  <div key={i} className={`p-2 rounded bg-white/5 border-l-2 ${theme.border}`}>
                    <div className="text-[10px] font-bold text-slate-400 uppercase">{f.name}</div>
                    <p className="text-[11px] text-slate-300">{f.reason}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex gap-4">
              <button 
                onClick={onClose}
                className="flex-1 py-4 bg-slate-800 border border-white/10 rounded-xl font-bold text-[10px] uppercase tracking-widest transition-colors hover:bg-slate-700"
              >
                {isSpam ? 'IGNORE' : 'Ignore'}
              </button>
              <button 
                onClick={onClose}
                className={`flex-1 py-4 rounded-xl font-bold text-[10px] uppercase tracking-widest transition-all text-white ${
                  isDangerous ? 'bg-red-600 hover:bg-red-500 shadow-lg shadow-red-900/50' : 
                  isSpam ? 'bg-orange-600 hover:bg-orange-500 shadow-lg shadow-orange-900/50' :
                  'bg-cyan-600 hover:bg-cyan-500 shadow-lg shadow-cyan-900/50'
                }`}
              >
                {isDangerous ? 'Force Block' : isSpam ? 'Screening Advised' : 'Connect'}
              </button>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}

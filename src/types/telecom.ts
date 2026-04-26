export type CallRiskLevel = 'safe' | 'suspicious' | 'dangerous';

export interface SIPMetadata {
  userAgent: string;
  pAssertedIdentity?: string;
  via: string[];
  contact: string;
  sourceIp: string;
  routingHops: number;
  isStirShakenVerified: boolean;
}

export interface RiskFactor {
  name: string;
  score: number; // 0 to 1
  impact: 'low' | 'medium' | 'high';
  reason: string;
}

export interface CallEvent {
  id: string;
  timestamp: string;
  callerNumber: string;
  callerName?: string;
  riskScore: number; // 0 to 100
  riskLevel: CallRiskLevel;
  factors: RiskFactor[];
  metadata: SIPMetadata;
  intent?: 'financial' | 'delivery' | 'personal' | 'scam' | 'unknown';
  status: 'allowed' | 'warned' | 'blocked';
}

export interface TelecomStats {
  activeCalls: number;
  blockedToday: number;
  avgRisk: number;
  threatLevel: 'normal' | 'elevated' | 'critical';
}

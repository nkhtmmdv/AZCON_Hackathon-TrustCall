import { CallEvent, CallRiskLevel, SIPMetadata } from '../types/telecom';

export const SIMULATED_CALLS: CallEvent[] = [
  {
    id: '1',
    timestamp: new Date().toISOString(),
    callerNumber: '+994 50 123 45 67',
    callerName: 'Azercell Customer Support',
    riskScore: 5,
    riskLevel: 'safe',
    status: 'allowed',
    intent: 'personal',
    factors: [
      { name: 'STIR/SHAKEN', score: 0, impact: 'low', reason: 'Verified Attestation A' },
      { name: 'Geo-Risk', score: 0, impact: 'low', reason: 'Domestic Source' }
    ],
    metadata: {
      userAgent: 'BroadSoft-Asterisk',
      sourceIp: '82.196.1.1',
      via: ['SIP/2.0/UDP 10.0.0.1'],
      contact: '<sip:caller@provider.com>',
      routingHops: 2,
      isStirShakenVerified: true
    }
  },
  {
    id: '2',
    timestamp: new Date().toISOString(),
    callerNumber: '+44 7700 900000',
    riskScore: 88,
    riskLevel: 'dangerous',
    status: 'blocked',
    intent: 'scam',
    factors: [
      { name: 'Spoofing Detection', score: 0.9, impact: 'high', reason: 'Neighbor Spoofing Pattern' },
      { name: 'Geo-Risk', score: 0.8, impact: 'high', reason: 'VOIP Gateway in High-Risk Zone' },
      { name: 'Behavior', score: 0.7, impact: 'medium', reason: 'Mass coordinate attack pattern' }
    ],
    metadata: {
      userAgent: 'MicroSIP/3.21',
      sourceIp: '185.234.12.1',
      via: ['SIP/2.0/TLS 192.168.1.5', 'SIP/2.0/UDP 45.1.2.3'],
      contact: '<sip:scammer@anonymous.org>',
      routingHops: 5,
      isStirShakenVerified: false
    }
  }
];

export function calculateRisk(metadata: SIPMetadata): number {
  let score = 0;
  if (!metadata.isStirShakenVerified) score += 30;
  if (metadata.routingHops > 4) score += 20;
  if (metadata.userAgent.toLowerCase().includes('microsip')) score += 15;
  // Simulating more logic...
  return Math.min(score + Math.random() * 20, 100);
}

export function getRiskLevel(score: number): CallRiskLevel {
  if (score < 30) return 'safe';
  if (score < 70) return 'suspicious';
  return 'dangerous';
}

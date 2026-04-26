export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function normalizePhoneNumber(input: string): string {
  const digitsOnly = input.replace(/\D/g, '');
  if (digitsOnly.startsWith('994')) return `+${digitsOnly}`;
  if (digitsOnly.length === 9) return `+994${digitsOnly}`;
  if (digitsOnly.length === 10 && digitsOnly.startsWith('0')) return `+994${digitsOnly.substring(1)}`;
  if (digitsOnly.length === 12 && digitsOnly.startsWith('994')) return `+${digitsOnly}`;
  return input.trim();
}

export function validateAzerbaijanPhone(number: string): boolean {
  return /^\+994\d{9}$/.test(number);
}

export function detectCarrier(phoneNumber: string): string {
  if (!phoneNumber.startsWith('+994')) return 'International';
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

export function mapRiskToStatus(risk: number): 'safe' | 'suspicious' | 'spam' | 'scam' {
  if (risk >= 85) return 'scam';
  if (risk >= 60) return 'spam';
  if (risk >= 30) return 'suspicious';
  return 'safe';
}

import { randomUUID } from 'node:crypto';

export function uuid(): string {
  return randomUUID();
}


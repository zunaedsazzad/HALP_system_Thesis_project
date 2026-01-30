import { Buffer } from 'buffer';

export function derivePseudonym(secret: string, context?: string): string {
  // TODO: derive pseudonym deterministically from secret/context
  return `pseudonym-${Buffer.from(secret + (context||'')).toString('hex').slice(0,8)}`;
}

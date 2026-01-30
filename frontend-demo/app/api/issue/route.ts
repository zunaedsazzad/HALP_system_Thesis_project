import { NextRequest, NextResponse } from 'next/server';

export async function POST(req: NextRequest) {
  const body = await req.json();
  // Proxy to issuer service; configure ISSUER_URL env var in your Next environment
  const issuerUrl = process.env.ISSUER_URL || 'http://localhost:3001/credentials/issue';
  const res = await fetch(issuerUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const data = await res.json();
  return NextResponse.json(data, { status: res.status });
}

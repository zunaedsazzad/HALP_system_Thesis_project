import { NextRequest, NextResponse } from 'next/server';

const VERIFIER_URL = process.env.VERIFIER_URL || 'http://localhost:3002';

/**
 * POST /api/auth
 * Proxy authentication requests to the verifier service
 * 
 * Supports two actions:
 * - action: 'challenge' - Request authentication challenge (Phase 1)
 * - action: 'verify' - Submit proof for verification (Phase 4)
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { action, ...payload } = body;

    let endpoint: string;
    
    switch (action) {
      case 'challenge':
        endpoint = `${VERIFIER_URL}/auth/challenge`;
        break;
      case 'verify':
        endpoint = `${VERIFIER_URL}/auth/verify`;
        break;
      default:
        // Legacy behavior: forward to verify endpoint
        endpoint = `${VERIFIER_URL}/auth/verify`;
    }

    console.log(`[API/Auth] Proxying ${action || 'verify'} request to ${endpoint}`);

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
    
  } catch (error) {
    console.error('[API/Auth] Proxy error:', error);
    return NextResponse.json(
      { 
        success: false, 
        error: 'Authentication service unavailable',
        details: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 503 }
    );
  }
}

/**
 * GET /api/auth
 * Get authentication status or challenge
 */
export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const domain = searchParams.get('domain') || 'default';

    const res = await fetch(`${VERIFIER_URL}/auth/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });

    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
    
  } catch (error) {
    console.error('[API/Auth] Challenge request error:', error);
    return NextResponse.json(
      { 
        success: false, 
        error: 'Unable to generate challenge'
      },
      { status: 503 }
    );
  }
}

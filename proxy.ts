import { NextResponse } from 'next/server';

// Apply the same browser protections when the console is opened directly on
// localhost as when it is served through the optional Caddy proxy.
export function proxy() {
  const response = NextResponse.next();
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('Referrer-Policy', 'no-referrer');
  response.headers.set(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=()',
  );
  response.headers.set(
    'Content-Security-Policy',
    "frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
  );
  response.headers.set('Cache-Control', 'no-store');
  return response;
}

export const config = {
  matcher: ['/', '/((?!_next/|assets/|favicon.svg|og.png).*)'],
};

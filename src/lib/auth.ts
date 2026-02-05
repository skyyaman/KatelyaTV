/* eslint-disable no-console */
import { NextRequest, NextResponse } from 'next/server';

// --- 直接把逻辑写在这里，不从外部 import ---
function getAuthInfoFromCookieInternal(request: NextRequest) {
  const authCookie = request.cookies.get('auth');
  if (!authCookie) return null;
  try {
    const decoded = decodeURIComponent(authCookie.value);
    return JSON.parse(decoded);
  } catch (error) {
    return null;
  }
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (shouldSkipAuth(pathname)) {
    return NextResponse.next();
  }

  const storageType = process.env.NEXT_PUBLIC_STORAGE_TYPE || 'localstorage';

  if (!process.env.AUTH_PASSWORD) {
    const warningUrl = new URL('/warning', request.url);
    return NextResponse.redirect(warningUrl);
  }

  // 使用内部定义的函数
  const authInfo = getAuthInfoFromCookieInternal(request);

  if (!authInfo) {
    return handleAuthFailure(request, pathname);
  }

  if (storageType === 'localstorage') {
    if (!authInfo.password || authInfo.password !== process.env.AUTH_PASSWORD) {
      return handleAuthFailure(request, pathname);
    }
    return NextResponse.next();
  }

  if (!authInfo.username || !authInfo.signature) {
    return handleAuthFailure(request, pathname);
  }

  if (authInfo.signature) {
    const isValidSignature = await verifySignature(
      authInfo.username,
      authInfo.signature,
      process.env.AUTH_PASSWORD || ''
    );

    if (isValidSignature) {
      return NextResponse.next();
    }
  }

  return handleAuthFailure(request, pathname);
}

// 验证签名（保持 Web Crypto API 实现，这是边缘兼容的）
async function verifySignature(
  data: string,
  signature: string,
  secret: string
): Promise<boolean> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(data);
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const signatureBuffer = new Uint8Array(
      signature.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
    );
    return await crypto.subtle.verify('HMAC', key, signatureBuffer, messageData);
  } catch (error) {
    console.error('签名验证失败:', error);
    return false;
  }
}

function handleAuthFailure(request: NextRequest, pathname: string): NextResponse {
  if (pathname.startsWith('/api')) {
    return new NextResponse('Unauthorized', { status: 401 });
  }
  const loginUrl = new URL('/login', request.url);
  const fullUrl = `${pathname}${request.nextUrl.search}`;
  loginUrl.searchParams.set('redirect', fullUrl);
  return NextResponse.redirect(loginUrl);
}

function shouldSkipAuth(pathname: string): boolean {
  const skipPaths = ['/_next', '/favicon.ico', '/robots.txt', '/manifest.json', '/icons/', '/logo.png', '/screenshot.png'];
  return skipPaths.some((path) => pathname.startsWith(path));
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|login|warning|api/login|api/register|api/logout|api/cron|api/server-config|api/search|api/detail|api/image-proxy|api/tvbox).*)',
  ],
  // 加上这个保险
  unstable_allowDynamic: ['**/node_modules/async_hooks/**'],
};

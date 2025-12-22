import { NextRequest, NextResponse } from 'next/server';

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:9100';

async function proxyRequest(
  request: NextRequest,
  { params }: { params: { path: string[] } }
) {
  try {
    const path = params.path.join('/');
    const url = new URL(`${BACKEND_URL}/${path}`);
    
    // Copy query parameters
    request.nextUrl.searchParams.forEach((value, key) => {
      url.searchParams.append(key, value);
    });

    // Get request body if present
    let body: string | undefined;
    const contentType = request.headers.get('content-type');
    
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      try {
        body = await request.text();
      } catch (e) {
        // No body
      }
    }

    // Forward headers (excluding host and connection)
    const headers: HeadersInit = {};
    const originalHost = request.headers.get('host');
    
    request.headers.forEach((value, key) => {
      const lowerKey = key.toLowerCase();
      if (
        lowerKey !== 'host' &&
        lowerKey !== 'connection' &&
        lowerKey !== 'content-length' &&
        lowerKey !== 'referer'
      ) {
        headers[key] = value;
      }
    });

    // Forward the original host as X-Forwarded-Host so backend knows the frontend URL
    if (originalHost) {
      headers['X-Forwarded-Host'] = originalHost;
    }

    // Explicitly forward cookies
    const cookieHeader = request.headers.get('cookie');
    if (cookieHeader) {
      headers['Cookie'] = cookieHeader;
    }

    // Make request to backend
    const response = await fetch(url.toString(), {
      method: request.method,
      headers,
      body: body || undefined,
      // Don't use credentials here as we're manually forwarding cookies
      redirect: 'manual',
    });

    // Get response body
    const responseBody = await response.text();
    
    // Create response with same status and headers
    const proxyResponse = new NextResponse(responseBody, {
      status: response.status,
      statusText: response.statusText,
    });

    // Forward all response headers (especially cookies)
    response.headers.forEach((value, key) => {
      const lowerKey = key.toLowerCase();
      // Forward important headers including set-cookie
      if (lowerKey === 'set-cookie') {
        // Adjust cookie attributes for Next.js domain
        let adjustedCookie = value;
        // Remove domain restriction entirely - let browser use default (current host)
        // This allows cookies to work on any host (localhost, IP addresses, etc.)
        adjustedCookie = adjustedCookie.replace(/;\s*[Dd]omain=[^;]+/gi, '');
        
        // Preserve other attributes like HttpOnly, Secure, Path
        // Only add SameSite if not already present
        if (!adjustedCookie.match(/;\s*[Ss]ame[Ss]ite=/i)) {
          adjustedCookie += '; SameSite=Lax';
        }
        proxyResponse.headers.append(key, adjustedCookie);
      } else if (
        lowerKey === 'content-type' ||
        lowerKey === 'content-length' ||
        lowerKey === 'cache-control'
      ) {
        proxyResponse.headers.set(key, value);
      }
    });

    return proxyResponse;
  } catch (error: any) {
    console.error('Proxy error:', error);
    return NextResponse.json(
      { error: 'Proxy error', message: error.message },
      { status: 500 }
    );
  }
}

export async function GET(
  request: NextRequest,
  context: { params: { path: string[] } }
) {
  return proxyRequest(request, context);
}

export async function POST(
  request: NextRequest,
  context: { params: { path: string[] } }
) {
  return proxyRequest(request, context);
}

export async function PUT(
  request: NextRequest,
  context: { params: { path: string[] } }
) {
  return proxyRequest(request, context);
}

export async function DELETE(
  request: NextRequest,
  context: { params: { path: string[] } }
) {
  return proxyRequest(request, context);
}

export async function PATCH(
  request: NextRequest,
  context: { params: { path: string[] } }
) {
  return proxyRequest(request, context);
}


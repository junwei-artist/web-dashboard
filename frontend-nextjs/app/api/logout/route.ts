import { NextRequest, NextResponse } from 'next/server';

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:9100';

export async function GET(request: NextRequest) {
  try {
    // Forward request to backend
    const cookieHeader = request.headers.get('cookie');
    const headers: HeadersInit = {};
    if (cookieHeader) {
      headers['Cookie'] = cookieHeader;
    }

    const response = await fetch(`${BACKEND_URL}/logout`, {
      method: 'GET',
      headers,
      redirect: 'manual',
    });

    const responseText = await response.text();
    
    // Create response
    const proxyResponse = new NextResponse(responseText, {
      status: response.status,
      statusText: response.statusText,
    });

    // Forward cookies from backend (for logout)
    response.headers.forEach((value, key) => {
      const lowerKey = key.toLowerCase();
      if (lowerKey === 'set-cookie') {
        // Remove domain restriction to work on any host
        let adjustedCookie = value;
        adjustedCookie = adjustedCookie.replace(/;\s*[Dd]omain=[^;]+/gi, '');
        if (!adjustedCookie.match(/;\s*[Ss]ame[Ss]ite=/i)) {
          adjustedCookie += '; SameSite=Lax';
        }
        proxyResponse.headers.append(key, adjustedCookie);
      } else if (lowerKey === 'content-type') {
        proxyResponse.headers.set(key, value);
      }
    });

    return proxyResponse;
  } catch (error: any) {
    console.error('Logout proxy error:', error);
    return NextResponse.json(
      { error: 'Logout proxy error', message: error.message },
      { status: 500 }
    );
  }
}


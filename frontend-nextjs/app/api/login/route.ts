import { NextRequest, NextResponse } from 'next/server';

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:9100';

export async function POST(request: NextRequest) {
  try {
    const body = await request.text();
    
    // Forward request to backend
    const cookieHeader = request.headers.get('cookie');
    const headers: HeadersInit = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };
    if (cookieHeader) {
      headers['Cookie'] = cookieHeader;
    }

    const response = await fetch(`${BACKEND_URL}/login`, {
      method: 'POST',
      headers,
      body: body,
      redirect: 'manual', // Don't follow redirects automatically
    });

    // Check if login was successful (302 redirect means success in Flask-Login)
    if (response.status === 302) {
      // Successful login - Flask returns redirect
      // Forward all cookies from the response
      const cookies: string[] = [];
      response.headers.forEach((value, key) => {
        if (key.toLowerCase() === 'set-cookie') {
          cookies.push(value);
        }
      });

      // Return success response with cookies
      const successResponse = NextResponse.json(
        { success: true, message: 'Login successful' },
        { status: 200 }
      );

      // Forward all set-cookie headers and adjust for Next.js domain
      const requestHost = request.headers.get('host') || 'localhost:9200';
      const hostname = requestHost.split(':')[0]; // Extract hostname without port
      
      cookies.forEach((cookie) => {
        // Adjust cookie attributes for Next.js domain
        let adjustedCookie = cookie;
        // Remove domain restriction entirely - let browser use default (current host)
        // This allows cookies to work on any host (localhost, IP addresses, etc.)
        adjustedCookie = adjustedCookie.replace(/;\s*[Dd]omain=[^;]+/gi, '');
        
        // Preserve other attributes like HttpOnly, Secure, Path
        // Only add SameSite if not already present
        if (!adjustedCookie.match(/;\s*[Ss]ame[Ss]ite=/i)) {
          adjustedCookie += '; SameSite=Lax';
        }
        successResponse.headers.append('Set-Cookie', adjustedCookie);
      });

      return successResponse;
    }

    // Status 200 - likely failed login (Flask returns login page with error)
    const responseText = await response.text();
    
    // Check if it contains error message
    // Flask login page on error contains "Invalid username or password" or similar
    if (responseText.includes('Invalid username') || 
        responseText.includes('Username and password are required') ||
        responseText.includes('error') ||
        responseText.includes('login.html')) {
      // Failed login
      const errorResponse = NextResponse.json(
        { 
          success: false, 
          error: 'Invalid username or password',
          message: 'Login failed. Please check your credentials.'
        },
        { status: 401 }
      );
      
      // Forward any cookies (though there shouldn't be any on failed login)
      response.headers.forEach((value, key) => {
        if (key.toLowerCase() === 'set-cookie') {
          errorResponse.headers.append(key, value);
        }
      });
      
      return errorResponse;
    }
    
    // If we get here with 200 and no clear error, might be success
    // But Flask typically uses 302 for success, so this is unusual
    // Forward cookies anyway and return success
    const cookies: string[] = [];
    response.headers.forEach((value, key) => {
      if (key.toLowerCase() === 'set-cookie') {
        cookies.push(value);
      }
    });
    
    const successResponse = NextResponse.json(
      { success: true, message: 'Login successful' },
      { status: 200 }
    );
    
    cookies.forEach((cookie) => {
      let adjustedCookie = cookie;
      adjustedCookie = adjustedCookie.replace(/;\s*[Dd]omain=[^;]+/gi, '');
      if (!adjustedCookie.includes('SameSite')) {
        adjustedCookie += '; SameSite=Lax';
      }
      successResponse.headers.append('Set-Cookie', adjustedCookie);
    });
    
    return successResponse;
  } catch (error: any) {
    console.error('Login proxy error:', error);
    return NextResponse.json(
      { 
        success: false,
        error: 'Login proxy error', 
        message: error.message 
      },
      { status: 500 }
    );
  }
}


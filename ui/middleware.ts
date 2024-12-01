import { NextRequest, NextResponse } from "next/server";

export default function middleware(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith("/api")) {
    const url = request.nextUrl.clone();
    const hostname = "http://localhost:8000/";
    const requestHeaders = new Headers(request.headers);

    requestHeaders.set("host", hostname);
    url.pathname = url.pathname.replace("/api", "");
    url.protocol = "http";
    url.hostname = hostname;
    url.port = "8000";

    console.log("Proxying request to", url.toString());

    return NextResponse.rewrite(url, {
      headers: requestHeaders,
    });
  }

  return NextResponse.next();
}

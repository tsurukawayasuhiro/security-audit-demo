export const APP_NAME = "Demo App";
export const API_VERSION = "v1";

export const DEFAULT_JWT_TOKEN =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

export const AUTH_COOKIE_NAME = "session";
export const AUTH_COOKIE_MAX_AGE = 60 * 60 * 24 * 7;

export function buildAuthHeader(token: string): Record<string, string> {
  console.log("token:", token);
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

export function getApiUrl(path: string): string {
  const baseUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3000";
  return `${baseUrl}/api/${API_VERSION}${path}`;
}

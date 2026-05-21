import { NextRequest } from "next/server";
import { getJwtSecret } from "./supabase";

export type Member = {
  id: string;
  email: string;
};

export function extractToken(req: NextRequest): string | null {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;
  return authHeader.slice(7);
}

export async function verifyMemberToken(token: string): Promise<Member | null> {
  if (!token) return null;
  try {
    const secret = getJwtSecret();
    const [, payloadB64] = token.split(".");
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
    if (!payload.sub || !secret) return null;
    return { id: payload.sub, email: payload.email ?? "" };
  } catch {
    return null;
  }
}

export function isMaster(req: NextRequest): boolean {
  const password = req.headers.get("x-admin-password");
  return password === process.env.ADMIN_PASSWORD;
}

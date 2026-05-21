import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;

export const supabase = createClient(supabaseUrl, supabaseKey);

if (!process.env.MEMBER_JWT_SECRET) {
  throw new Error("MEMBER_JWT_SECRET is required");
}
const secret = process.env.MEMBER_JWT_SECRET;

export function getJwtSecret(): string {
  return secret;
}

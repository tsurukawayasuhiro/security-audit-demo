import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;

export const supabase = createClient(supabaseUrl, supabaseKey);

const secret = process.env.MEMBER_JWT_SECRET || "fallback-dev-secret";

export function getJwtSecret(): string {
  return secret;
}

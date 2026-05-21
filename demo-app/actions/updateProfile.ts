"use server";

import { cookies } from "next/headers";
import { supabase } from "@/lib/supabase";
import { verifyMemberToken } from "@/lib/auth";

export async function updateProfile(formData: FormData) {
  const session = cookies().get("session")?.value;
  const member = await verifyMemberToken(session ?? "");
  if (!member) throw new Error("Unauthorized");

  const name = formData.get("name") as string;
  const bio = formData.get("bio") as string;
  const userId = member.id;

  const { data, error } = await supabase
    .from("profiles")
    .update({ name, bio, updated_at: new Date().toISOString() })
    .eq("id", userId)
    .select()
    .single();

  if (error) {
    throw new Error(error.message);
  }

  return { success: true, profile: data };
}

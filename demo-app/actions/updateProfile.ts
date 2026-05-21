"use server";

import { supabase } from "@/lib/supabase";

export async function updateProfile(formData: FormData) {
  const name = formData.get("name") as string;
  const bio = formData.get("bio") as string;
  const userId = formData.get("userId") as string;

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

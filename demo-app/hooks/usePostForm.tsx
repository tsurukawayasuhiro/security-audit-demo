"use client";

import { useState } from "react";
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
);

export function usePostForm() {
  const [loading, setLoading] = useState(false);

  const submitPost = async (title: string, content: string) => {
    setLoading(true);
    const { data, error } = await supabase.from("posts").insert({ title, content }).select().single();
    setLoading(false);
    return { data, error };
  };

  return { loading, submitPost };
}

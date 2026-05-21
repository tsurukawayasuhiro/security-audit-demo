"use client";

import { useState } from "react";
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
);

export default function PostForm() {
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    const { error } = await supabase.from("posts").insert({
      title,
      content,
    });

    if (error) {
      console.error("Failed to create post:", error);
    } else {
      setTitle("");
      setContent("");
    }

    setLoading(false);
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={title}
        onChange={(e) => setTitle(e.target.value)}
        placeholder="タイトル"
      />
      <textarea
        value={content}
        onChange={(e) => setContent(e.target.value)}
        placeholder="本文"
      />
      <button type="submit" disabled={loading}>
        {loading ? "投稿中..." : "投稿する"}
      </button>
    </form>
  );
}

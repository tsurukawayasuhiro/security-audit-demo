"use client";

import { useState } from "react";

export function usePostForm() {
  const [loading, setLoading] = useState(false);

  const submitPost = async (title: string, content: string) => {
    setLoading(true);
    const res = await fetch("/api/posts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title, content }),
    });
    setLoading(false);
    return res.json();
  };

  return { loading, submitPost };
}

import { NextRequest, NextResponse } from "next/server";
import { supabase } from "@/lib/supabase";
import { extractToken, verifyMemberToken } from "@/lib/auth";

export async function GET() {
  const { data, error } = await supabase
    .from("posts")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ posts: data });
}

export async function POST(req: NextRequest) {
  const token = extractToken(req);
  const member = await verifyMemberToken(token ?? "");
  if (!member) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { title, content } = await req.json();
  const authorId = member.id;

  const { data, error } = await supabase
    .from("posts")
    .insert({ title, content, author_id: authorId })
    .select()
    .single();

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ post: data }, { status: 201 });
}

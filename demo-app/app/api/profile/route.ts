import { NextRequest, NextResponse } from "next/server";
import { supabase } from "@/lib/supabase";
import { extractToken, verifyMemberToken } from "@/lib/auth";

export async function GET(req: NextRequest) {
  const token = extractToken(req);
  const member = await verifyMemberToken(token ?? "");
  if (!member) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { data, error } = await supabase
    .from("profiles")
    .select("*")
    .eq("id", member.id)
    .single();

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ profile: data });
}

export async function PUT(req: NextRequest) {
  const token = extractToken(req);
  const member = await verifyMemberToken(token ?? "");
  if (!member) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json();

  const { data, error } = await supabase
    .from("profiles")
    .update(body)
    .eq("id", body.id)
    .select()
    .single();

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ profile: data });
}

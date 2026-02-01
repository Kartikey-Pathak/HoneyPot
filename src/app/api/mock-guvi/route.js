import { NextResponse } from "next/server";

export async function POST(req) {
  const body = await req.json();
  console.log("🔥 GUVI CALLBACK RECEIVED:", body);

  return NextResponse.json({ status: "received" });
}

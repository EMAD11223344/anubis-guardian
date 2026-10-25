import jwt from "jsonwebtoken";

// clean cases: JWT-001/002 — verify with pinned algorithms; decode for display only
export function verifySession(token: string): unknown {
  return jwt.verify(token, process.env.JWT_SECRET as string, { algorithms: ["HS256"] });
}

export function sessionPreview(token: string) {
  const preview = jwt.decode(token) as { sub?: string; email?: string } | null;
  return { subject: preview?.sub, email: preview?.email };
}

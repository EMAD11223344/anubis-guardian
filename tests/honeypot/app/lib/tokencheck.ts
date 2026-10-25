import jwt from "jsonwebtoken";

// honeypot seed: JWT-001 — jwt.decode() (no signature check) feeding a role decision.
export function roleFromToken(token: string): string {
  const payload = jwt.decode(token) as { role?: string; sub?: string } | null;
  if (payload?.role === "admin") return "admin";
  return "user";
}

// honeypot seed: JWT-002 — verification with algorithms:"none" AND ignoreExpiration:true
export function verifySession(token: string): unknown {
  return jwt.verify(token, process.env.JWT_SECRET as string, {
    algorithms: ["none", "HS256"],
    ignoreExpiration: true,
  });
}

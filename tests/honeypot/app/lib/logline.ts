// honeypot seed: LOGS-001 — secret-shaped literal + token var flowing into logs
export function debugSession(token: string) {
  // literal JWT in a log call → HIGH (the credential lives in log storage now)
  console.log("session for debugging:", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzZWVkLTMxIn0.Z0VF8xK2mQ0zqLw2vNfHk1YtP5jR9sUuB3oX7eCdA6w");
  // token-shaped variable into a log call → MEDIUM (verify masking upstream)
  if (process.env.DEBUG === "1") console.log("auth token:", token);
}

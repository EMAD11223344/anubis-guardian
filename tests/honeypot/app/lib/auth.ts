// honeypot seed: CRYPTO-001 — predictable security material
export function generateResetToken(): string {
  const token = Math.random().toString(36).slice(2) + Date.now().toString(36);
  return token;
}

export function makeOtp(): string {
  return String(Math.floor(Math.random() * 900000) + 100000);
}

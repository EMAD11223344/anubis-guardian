// clean cases: LOGS-001 — masked token before logging + identifiers only
export function auditLine(orderId: string, rows: { length: number }) {
  console.log("order processed", { orderId, count: rows.length });
}

export function debugMasked(token: string) {
  // masked before it reaches the logger — the clean pattern
  console.log("masked token:", token.slice(0, 4) + "…(hashed in audit)");
}

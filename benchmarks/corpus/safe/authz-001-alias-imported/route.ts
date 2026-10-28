import { handler } from "@/lib/handler";

// Re-exported import under a method name: the analyzer has NO local body to
// analyze, so no handler — and no missing-authz review — is fabricated here.
export { handler as DELETE };

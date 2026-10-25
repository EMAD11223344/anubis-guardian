// honeypot seed: SUPA-003 — Edge Function builds a service_role client with no
// caller authentication: whoever can invoke the function URL gets admin reads.
import { createClient } from "jsr:@supabase/supabase-js@2";

const admin = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
);

Deno.serve(async () => {
  const { data } = await admin.from("profiles").select("*");
  return Response.json({ rows: data });
});

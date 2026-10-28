import { createClient } from '@supabase/supabase-js';

// Server-only data module: the service-role key stays in process.env and the
// module is only imported from server code (a 'use client' component reaching
// it through the @safe/* alias would make it client-reachable — that is the
// vulnerable counterpart in vuln/secrets-client-alias).
export async function fetchPublicData() {
  const admin = createClient(
    process.env.SUPABASE_URL as string,
    process.env.SUPABASE_SERVICE_ROLE_KEY as string
  );
  return admin.from('users').select('id');
}

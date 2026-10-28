import { createClient } from '@supabase/supabase-js';

const SUPABASE_SERVICE_ROLE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRlbW9rZXkiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzM1Njg5NjAwLCJleHAiOjE4OTM0NTYwMDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

export async function fetchAdminData() {
  const admin = createClient('https://demokey.supabase.co', SUPABASE_SERVICE_ROLE_KEY);
  return admin.from('users').select('*');
}

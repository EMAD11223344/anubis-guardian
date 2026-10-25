'use client';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  'https://demokey.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRlbW9rZXkiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzM1Njg5NjAwLCJleHAiOjE4OTM0NTYwMDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
);

export default function AdminPanel() {
  return <button onClick={() => supabase.from('users').select('*')}>Load all users</button>;
}

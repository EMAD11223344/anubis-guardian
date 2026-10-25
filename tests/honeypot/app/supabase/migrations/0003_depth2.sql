-- honeypot seeds: SUPA-R06 unscoped policy + SUPA-R07 storage bucket without object RLS
CREATE TABLE public.sessions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users,
  token text
);

CREATE POLICY "sessions_read" ON public.sessions FOR SELECT USING (true);

INSERT INTO storage.buckets (id, name, public)
VALUES ('uploads', 'uploads', false);

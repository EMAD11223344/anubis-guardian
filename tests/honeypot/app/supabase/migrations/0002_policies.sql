CREATE POLICY "everyone_read" ON public.users
  FOR SELECT USING (true);

CREATE POLICY "anon_write_profiles" ON public.profiles
  FOR INSERT WITH CHECK (true);

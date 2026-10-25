-- clean case: SUPA-002 — server-managed app_metadata inside an auth.uid()-scoped
-- policy (the safe counterpart of the user_metadata honeypot seed).
create policy "clean_org_read" on public.profiles
  for select to authenticated
  using (
    auth.uid() = user_id
    and coalesce(auth.jwt() -> 'app_metadata' ->> 'org', '') <> ''
  );

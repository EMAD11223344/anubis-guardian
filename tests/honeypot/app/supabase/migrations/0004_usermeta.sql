-- honeypot seed: SUPA-002 — RLS authorization pinned to user-writable metadata.
-- auth.user_metadata is editable by the user via updateUser() ⇒ any user can
-- self-assign the "admin" role by editing their own metadata.
create policy "role_from_metadata" on public.profiles
  for select to authenticated
  using (coalesce(auth.jwt() -> 'user_metadata' ->> 'role', 'user') = 'admin' or auth.uid() = user_id);

CREATE TABLE public.profiles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users,
  full_name text,
  phone text,
  billing_address text
);

CREATE TABLE public.posts (
  id uuid primary key default gen_random_uuid(),
  author uuid references auth.users,
  body text
);
ALTER TABLE public.posts ENABLE ROW LEVEL SECURITY;

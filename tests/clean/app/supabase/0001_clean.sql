CREATE TABLE public.posts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users,
  body text
);
ALTER TABLE public.posts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "owner_read" ON public.posts
  FOR SELECT USING (auth.uid() = user_id);

CREATE VIEW public.posts_view WITH (security_invoker = true) AS
  SELECT * FROM public.posts;

CREATE FUNCTION public.get_stats() RETURNS TABLE (cnt bigint)
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
    SELECT count(*) FROM public.posts;
  $$;

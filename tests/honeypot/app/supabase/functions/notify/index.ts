// honeypot seed: SUPA-R08 edge function
Deno.serve(async (req) => {
  const body = await req.json();
  return new Response(JSON.stringify({ ok: true, body }), { headers: { "Content-Type": "application/json" } });
});

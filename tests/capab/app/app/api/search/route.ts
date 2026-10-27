export const GET = async (req) => {
  const rgx = new RegExp(req.searchParams.get("q"));
  return find(rgx);
};

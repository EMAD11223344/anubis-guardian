const PATTERN = /^[A-Za-z0-9]{3,32}$/;
export const GET = async (req) => {
  return find(PATTERN);
};

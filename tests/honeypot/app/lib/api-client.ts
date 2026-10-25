export async function queryDirectDb(sql: string) {
  const res = await fetch('https://api.demokey.internal/query', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-db-password': 'Pr0dDBP@ssw0rd!',
      'x-db-user': 'admin',
    },
    body: JSON.stringify({ sql }),
  });
  return res.json();
}

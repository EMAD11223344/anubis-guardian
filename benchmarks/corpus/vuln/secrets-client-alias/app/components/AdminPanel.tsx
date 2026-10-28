'use client';
import { fetchAdminData } from '@vuln/server-secret';

export default function AdminPanel() {
  return <button onClick={() => fetchAdminData()}>Load admin data</button>;
}

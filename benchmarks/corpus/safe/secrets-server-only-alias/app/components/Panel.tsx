'use client';
import { fetchPublicData } from '@safe/env-only';

export default function Panel() {
  return <button onClick={() => fetchPublicData()}>Load data</button>;
}

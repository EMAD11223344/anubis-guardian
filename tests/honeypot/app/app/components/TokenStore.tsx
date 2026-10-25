'use client';

export function saveSession(token: string) {
  localStorage.setItem('auth_token', token);
  sessionStorage.setItem('refresh_token', token);
}

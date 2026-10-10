import { supabase } from './supabase';

export async function getAccessToken() {
  const { data, error } = await supabase.auth.getSession();
  if (error || !data?.session?.access_token) {
    throw new Error('Sign in to access investigations');
  }
  return data.session.access_token;
}

export async function apiFetch(url, options = {}) {
  const token = await getAccessToken();
  const headers = new Headers(options.headers);
  headers.set('Authorization', `Bearer ${token}`);
  return fetch(url, { ...options, headers });
}

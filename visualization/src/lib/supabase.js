import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || 'http://localhost:54321';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || 'dummy-anon-key';

if (!import.meta.env.VITE_SUPABASE_URL || !import.meta.env.VITE_SUPABASE_ANON_KEY) {
  console.warn(
    '[Specula] Missing Supabase env vars. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in your .env file.'
  );
}

// Sanitize URL in case /rest/v1 or trailing slashes were included
const cleanUrl = supabaseUrl ? supabaseUrl.replace(/\/rest\/v1\/?$/, '').replace(/\/+$/, '') : '';

export const supabase = createClient(cleanUrl, supabaseAnonKey);

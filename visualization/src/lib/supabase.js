import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

let supabaseInstance;

if (!supabaseUrl || !supabaseAnonKey) {
  console.warn(
    '[Specula] Missing Supabase env vars. Using MOCK client for UI preview. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY to enable real auth.'
  );
  
  // Provide a mock client that simulates a logged-in user so the UI can be previewed
  supabaseInstance = {
    auth: {
      getSession: async () => ({
        data: {
          session: {
            user: { id: 'mock-user-id', email: 'investigator@specula.local' },
          }
        }
      }),
      onAuthStateChange: (callback) => {
        // Immediately trigger logged-in state
        setTimeout(() => callback('SIGNED_IN', { user: { id: 'mock-user-id', email: 'investigator@specula.local' } }), 100);
        return { data: { subscription: { unsubscribe: () => {} } } };
      },
      signUp: async () => ({ data: { user: null }, error: new Error('Mock client cannot sign up') }),
      signInWithPassword: async () => ({ data: { user: null }, error: new Error('Mock client cannot sign in') }),
      signOut: async () => {},
    },
    from: (table) => ({
      select: () => ({
        eq: () => ({
          single: async () => ({
            data: { id: 'mock-user-id', full_name: 'Mock Investigator', role: 'admin' },
            error: null
          })
        })
      }),
      upsert: async () => ({ error: null })
    })
  };
} else {
  // Sanitize URL in case /rest/v1 or trailing slashes were included
  const cleanUrl = supabaseUrl.replace(/\/rest\/v1\/?$/, '').replace(/\/+$/, '');
  supabaseInstance = createClient(cleanUrl, supabaseAnonKey);
}

export const supabase = supabaseInstance;

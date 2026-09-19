import { createContext, useContext, useEffect, useState } from 'react';
import { supabase } from '../lib/supabase';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [session, setSession] = useState(undefined); // undefined = loading
  const [profile, setProfile] = useState(null);

  // Fetch user profile from public.users table
  async function fetchProfile(userId) {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', userId)
      .single();
    if (!error) setProfile(data);
    return data;
  }

  useEffect(() => {
    // Get current session on mount
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      if (session?.user) fetchProfile(session.user.id);
    });

    // Listen for auth state changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
      if (session?.user) {
        fetchProfile(session.user.id);
      } else {
        setProfile(null);
      }
    });

    return () => subscription.unsubscribe();
  }, []);

  async function signUp({ email, password, fullName }) {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          full_name: fullName,
        },
      },
    });
    if (error) throw error;

    // If an active session exists (e.g. Email Confirmation disabled), attempt client-side insert into public.users.
    // If a Postgres trigger handles it or email confirmation is pending, catch profileError safely.
    if (data.user) {
      const { error: profileError } = await supabase.from('users').upsert(
        {
          id: data.user.id,
          email,
          full_name: fullName,
          role: 'investigator',
        },
        { onConflict: 'id' }
      );
      if (profileError) {
        console.warn('[Specula] Profile insert notice (may be handled by DB trigger or email confirmation required):', profileError.message);
      }
    }
    return data;
  }

  async function signIn({ email, password }) {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) throw error;
    return data;
  }

  async function signOut() {
    await supabase.auth.signOut();
    setProfile(null);
  }

  const value = {
    session,
    profile,
    user: session?.user ?? null,
    isLoading: session === undefined,
    isAuthenticated: !!session,
    signUp,
    signIn,
    signOut,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}

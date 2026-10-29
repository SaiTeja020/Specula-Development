import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'vite';
import React from 'react';
import { renderToString } from 'react-dom/server';

test('guest enters without Supabase, survives reload, and signs out locally', async () => {
  const stored = new Map();
  globalThis.sessionStorage = {
    getItem: key => stored.get(key) ?? null,
    setItem: (key, value) => stored.set(key, value),
    removeItem: key => stored.delete(key),
  };
  const server = await createServer({
    root: new URL('../', import.meta.url).pathname.replace(/^\/(\w:)/, '$1'),
    server: { middlewareMode: true },
  });
  try {
    const { AuthProvider, useAuth } = await server.ssrLoadModule('/src/contexts/AuthContext.jsx');
    const { getAccessToken } = await server.ssrLoadModule('/src/lib/api.js');
    let auth;
    function Probe() { auth = useAuth(); return null; }
    const render = () => renderToString(React.createElement(AuthProvider, null, React.createElement(Probe)));
    render();
    assert.equal(auth.isAuthenticated, false);
    auth.signInAsGuest();
    render();
    assert.equal(auth.isAuthenticated, true);
    assert.equal(auth.isLoading, false);
    assert.equal(auth.profile.full_name, 'Guest');
    assert.equal(auth.session, undefined); // No fabricated Supabase credential.
    await assert.rejects(getAccessToken(), /Guest mode supports local investigations/);
    await auth.signOut();
    render();
    assert.equal(auth.isGuest, false);
    assert.equal(auth.isAuthenticated, false);
  } finally {
    await server.close();
    delete globalThis.sessionStorage;
  }
});

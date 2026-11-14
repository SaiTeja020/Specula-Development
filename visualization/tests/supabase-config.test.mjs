import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

function load(env) {
  const source = readFileSync(new URL('../src/lib/supabase.js', import.meta.url), 'utf8')
    .replace(/^import .*;\r?\n/m, '')
    .replaceAll('import.meta.env', 'env')
    .replace('export const supabase', 'const supabase');
  const calls = [];
  const client = {};
  const supabase = new Function('env', 'createClient', 'console', source + '\nreturn supabase;')(
    env, (...args) => { calls.push(args); return client; }, { warn() {} });
  return { supabase, calls, client };
}

test('absent or partial Supabase settings leave account sign-in unconfigured', () => {
  for (const env of [{}, { VITE_SUPABASE_URL: 'https://example.test' }, { VITE_SUPABASE_ANON_KEY: 'test-key' }]) {
    const result = load(env);
    assert.equal(result.supabase, null);
    assert.deepEqual(result.calls, []);
  }
});

test('configured Supabase credentials reach the client with a normalized URL', () => {
  const result = load({ VITE_SUPABASE_URL: 'https://example.test/rest/v1/', VITE_SUPABASE_ANON_KEY: 'test-key' });
  assert.equal(result.supabase, result.client);
  assert.deepEqual(result.calls, [['https://example.test', 'test-key']]);
});

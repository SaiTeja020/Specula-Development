const GUEST_KEY = 'specula.guest';

export const guestProfile = { id: 'guest', full_name: 'Guest', role: 'guest' };

export function isGuestSession() {
  return sessionStorage.getItem(GUEST_KEY) === '1';
}

export function setGuestSession(enabled) {
  if (enabled) sessionStorage.setItem(GUEST_KEY, '1');
  else sessionStorage.removeItem(GUEST_KEY);
}

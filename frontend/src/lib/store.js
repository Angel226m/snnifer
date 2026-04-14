import { writable } from 'svelte/store';

// Auth store
export const authStore = writable({
  token: null,
  user: null,
  isAuthenticated: false,
  loading: false,
  error: null
});

// Clients store
export const clientsStore = writable({
  clients: [],
  loading: false,
  error: null,
  total: 0
});

// Initialize stores from localStorage
export function initializeStores() {
  if (typeof window !== 'undefined') {
    const savedToken = localStorage.getItem('jwt_token');
    const savedUser = localStorage.getItem('user');

    if (savedToken && savedUser) {
      authStore.set({
        token: savedToken,
        user: JSON.parse(savedUser),
        isAuthenticated: true,
        loading: false,
        error: null
      });
    }
  }
}

// Clear auth on logout
export function logout() {
  localStorage.removeItem('jwt_token');
  localStorage.removeItem('user');
  authStore.set({
    token: null,
    user: null,
    isAuthenticated: false,
    loading: false,
    error: null
  });
}

import axios from 'axios';
import { authStore } from './store';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

let currentToken = null;

// Subscribe to auth store to keep token in sync
authStore.subscribe(value => {
  currentToken = value.token;
});

// Create axios instance
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Add token to requests
api.interceptors.request.use(
  config => {
    if (currentToken) {
      config.headers.Authorization = `Bearer ${currentToken}`;
    }
    return config;
  },
  error => Promise.reject(error)
);

// Handle response errors
api.interceptors.response.use(
  response => response,
  error => {
    if (error.response?.status === 401) {
      // Token expired or invalid
      authStore.set({
        token: null,
        user: null,
        isAuthenticated: false,
        loading: false,
        error: 'Session expired. Please login again.'
      });
    }
    return Promise.reject(error);
  }
);

// Auth API
export const authAPI = {
  register: (email, password) =>
    api.post('/auth/register', { email, password }),

  login: (email, password) =>
    api.post('/auth/login', { email, password }),

  getCurrentUser: () =>
    api.get('/auth/me')
};

// Clients API
export const clientsAPI = {
  getClients: () =>
    api.get('/clients'),

  getClient: (clientId) =>
    api.get(`/clients/${clientId}`),

  createClient: (clientData) =>
    api.post('/clients', clientData),

  updateClient: (clientId, clientData) =>
    api.put(`/clients/${clientId}`, clientData),

  deleteClient: (clientId) =>
    api.delete(`/clients/${clientId}`)
};

export default api;

import axios from 'axios';
import { w as writable } from './index-DWyUw6A5.js';

const authStore = writable({
  token: null,
  user: null,
  isAuthenticated: false,
  loading: false,
  error: null
});
const clientsStore = writable({
  clients: [],
  loading: false,
  error: null,
  total: 0
});
const API_URL = "http://localhost:8000";
let currentToken = null;
authStore.subscribe((value) => {
  currentToken = value.token;
});
const api = axios.create({
  baseURL: API_URL,
  headers: {
    "Content-Type": "application/json"
  }
});
api.interceptors.request.use(
  (config) => {
    if (currentToken) {
      config.headers.Authorization = `Bearer ${currentToken}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      authStore.set({
        token: null,
        user: null,
        isAuthenticated: false,
        loading: false,
        error: "Session expired. Please login again."
      });
    }
    return Promise.reject(error);
  }
);

export { clientsStore as c };
//# sourceMappingURL=api-FNLPj6bw.js.map

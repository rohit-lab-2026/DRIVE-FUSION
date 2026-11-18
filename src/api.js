// ---------------------------------------------------------------------------
// Auth layer: talks to the real Express server in /server, which stores
// accounts in MongoDB Atlas (see server/db.js) and emails OTPs via Brevo.
// Account data is no longer kept in localStorage — only the logged-in
// session (token + user info) is, same as before.
//
// Exported interface is unchanged: authApi.register/login/verifyOtp/
// forgotPassword/resetPassword, saveSession, clearSession, getCurrentUser —
// so AuthPage.jsx / App.jsx don't need any changes.
// ---------------------------------------------------------------------------

// In production the Express server also serves the built frontend, so the API
// lives on the same origin (empty string). In dev it defaults to localhost.
// Set VITE_API_URL at build time only if the API is hosted somewhere else.
const SERVER_URL = import.meta.env.VITE_API_URL ?? (import.meta.env.PROD ? '' : 'http://localhost:4040');

class ApiError extends Error {}

// `credentials: 'include'` is required so the session cookie the server sets
// (used to check OTPs) is sent back on the next request, even across ports
// in local dev.
async function apiRequest(path, body) {
  let response;
  try {
    response = await fetch(`${SERVER_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(body),
    });
  } catch {
    throw new ApiError('Could not reach the server. Is it running on ' + (SERVER_URL || 'this site') + '?');
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new ApiError(data.message || 'Request failed.');
  return data;
}

export const authApi = {
  register({ fullName, email, password }) {
    return apiRequest('/api/register', { fullName, email, password });
  },

  login({ email, password }) {
    return apiRequest('/api/login', { email, password });
  },

  verifyOtp({ email, otp }) {
    return apiRequest('/api/verify-otp', { email, otp });
  },

  forgotPassword({ email }) {
    return apiRequest('/api/forgot-password', { email });
  },

  resetPassword({ email, otp, newPassword }) {
    return apiRequest('/api/reset-password', { email, otp, newPassword });
  },
};

export function saveSession(response) {
  if (response?.token) localStorage.setItem('drivefusion_token', response.token);
  if (response?.user) localStorage.setItem('drivefusion_user', JSON.stringify(response.user));
}

export function clearSession() {
  localStorage.removeItem('drivefusion_token');
  localStorage.removeItem('drivefusion_user');
}

export async function getCurrentUser() {
  const token = localStorage.getItem('drivefusion_token');
  const userRaw = localStorage.getItem('drivefusion_user');
  if (!token || !userRaw) return null;
  try {
    return JSON.parse(userRaw);
  } catch {
    return null;
  }
}

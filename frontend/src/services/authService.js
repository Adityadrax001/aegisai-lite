
const API_BASE = "/api/auth";

async function request(endpoint, options = {}) {
  let response;

  try {
    response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    });
  } catch {
    throw new Error("Unable to connect to authentication server");
  }

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.message || `Authentication failed (${response.status})`
    );
  }

  return data;
}

export const authService = {
  login(email, password) {
    return request("/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
  },

  getCurrentAdmin() {
    return request("/me");
  },

  logout() {
    return request("/logout", {
      method: "POST",
    });
  },
};

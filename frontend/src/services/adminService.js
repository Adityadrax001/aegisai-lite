
export const adminService = {
  async getAdmins() {
    const response = await fetch("/api/admins", {
      method: "GET",
      credentials: "include",
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(
        data.message || "Unable to fetch administrators"
      );
    }

    if (!Array.isArray(data.admins)) {
      throw new Error("Invalid administrators response");
    }

    return data.admins;
  },

  async createAdmin({ name, email, password }) {
    const response = await fetch("/api/admins", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-Aegis-Request": "browser",
      },
      body: JSON.stringify({ name, email, password }),
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(
        data.message || "Unable to create administrator"
      );
    }

    return data;
  },
};

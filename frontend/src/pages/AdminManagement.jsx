
import { useState, useEffect } from "react";
import { ShieldPlus, UserRoundPlus, UsersRound } from "lucide-react";
import { z } from "zod";

import { adminService } from "../services/adminService";

const schema = z.object({
  name: z.string().trim().min(2, "Name must have at least 2 characters").max(100),
  email: z.email("Enter a valid email address").max(254),
  password: z.string().min(12, "Password must have at least 12 characters").max(128),
});

export default function AdminManagement() {
  const [form, setForm] = useState({
    name: "",
    email: "",
    password: "",
  });

  const [admins, setAdmins] = useState([]);
  const [loadingAdmins, setLoadingAdmins] = useState(true);
  const [adminListError, setAdminListError] = useState("");

  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  // Fetch admins when the page opens.
  useEffect(() => {
    let active = true;

    async function fetchAdmins() {
      try {
        const result = await adminService.getAdmins();

        if (active) {
          setAdmins(result);
          setAdminListError("");
        }
      } catch (err) {
        if (active) {
          setAdminListError(err.message || "Unable to load administrators");
        }
      } finally {
        if (active) {
          setLoadingAdmins(false);
        }
      }
    }

    fetchAdmins();

    return () => {
      active = false;
    };
  }, []);

  // Reload the admin list after creating a new admin.
  async function loadAdmins() {
    setLoadingAdmins(true);
    setAdminListError("");

    try {
      const result = await adminService.getAdmins();
      setAdmins(result);
    } catch (err) {
      setAdminListError(err.message || "Unable to load administrators");
    } finally {
      setLoadingAdmins(false);
    }
  }

  function update(field, value) {
    setForm((previous) => ({
      ...previous,
      [field]: value,
    }));
  }

  async function handleSubmit(event) {
    event.preventDefault();

    setError("");
    setMessage("");

    const parsed = schema.safeParse({
      ...form,
      email: form.email.trim().toLowerCase(),
    });

    if (!parsed.success) {
      setError(parsed.error.issues[0].message);
      return;
    }

    setPending(true);

    try {
      const result = await adminService.createAdmin(parsed.data);

      setMessage(
        `Administrator ${result.admin.email} created successfully.`
      );

      setForm({
        name: "",
        email: "",
        password: "",
      });

      await loadAdmins();
    } catch (err) {
      setError(err.message || "Unable to create administrator");
    } finally {
      setPending(false);
    }
  }

  const inputClass =
    "w-full border-2 border-black bg-bg px-4 py-3 outline-none focus:ring-2 focus:ring-lime";

  return (
    <main className="max-w-3xl space-y-6">
      {/* PAGE HEADER */}
      <header>
        <div className="flex items-center gap-3">
          <ShieldPlus size={34} />

          <h1 className="text-3xl font-black">
            ADMIN MANAGEMENT
          </h1>
        </div>

        <p className="mt-2 text-sm text-muted">
          Manage authorized AegisAI-Lite administrators.
        </p>
      </header>

      {/* CREATE ADMIN SECTION */}
      <section className="nb-card space-y-5 p-6">
        <div className="flex items-center gap-3">
          <UserRoundPlus size={24} />

          <h2 className="text-xl font-black">
            CREATE ADMIN ACCOUNT
          </h2>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label
              htmlFor="new-admin-name"
              className="mb-2 block font-bold"
            >
              Full name
            </label>

            <input
              id="new-admin-name"
              className={inputClass}
              value={form.name}
              onChange={(e) => update("name", e.target.value)}
              autoComplete="off"
              required
            />
          </div>

          <div>
            <label
              htmlFor="new-admin-email"
              className="mb-2 block font-bold"
            >
              Email address
            </label>

            <input
              id="new-admin-email"
              type="email"
              className={inputClass}
              value={form.email}
              onChange={(e) => update("email", e.target.value)}
              autoComplete="off"
              required
            />
          </div>

          <div>
            <label
              htmlFor="new-admin-password"
              className="mb-2 block font-bold"
            >
              Initial password
            </label>

            <input
              id="new-admin-password"
              type="password"
              className={inputClass}
              value={form.password}
              onChange={(e) => update("password", e.target.value)}
              autoComplete="new-password"
              minLength={12}
              required
            />

            <p className="mt-1 text-xs text-muted">
              Use a unique password of at least 12 characters.
            </p>
          </div>

          {error && (
            <p
              role="alert"
              className="border-2 border-black bg-[#FFD5D0] p-3 font-bold text-black"
            >
              {error}
            </p>
          )}

          {message && (
            <p
              role="status"
              className="border-2 border-black bg-lime p-3 font-bold text-black"
            >
              {message}
            </p>
          )}

          <button
            type="submit"
            disabled={pending}
            className="border-2 border-black bg-lime px-6 py-3 font-black text-black shadow-[4px_4px_0_#111] disabled:opacity-60"
          >
            {pending ? "CREATING..." : "CREATE ADMIN"}
          </button>
        </form>
      </section>

      {/* REGISTERED ADMINS SECTION */}
      <section className="nb-card space-y-5 p-6">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <UsersRound size={24} />

            <h2 className="text-xl font-black">
              REGISTERED ADMINISTRATORS
            </h2>
          </div>

          <button
            type="button"
            onClick={loadAdmins}
            disabled={loadingAdmins}
            className="border-2 border-black bg-lime px-3 py-2 text-xs font-black text-black disabled:opacity-60"
          >
            REFRESH
          </button>
        </div>

        {loadingAdmins ? (
          <p role="status" className="font-bold text-muted">
            Loading administrators...
          </p>
        ) : adminListError ? (
          <p
            role="alert"
            className="border-2 border-black bg-[#FFD5D0] p-3 font-bold text-black"
          >
            {adminListError}
          </p>
        ) : admins.length === 0 ? (
          <p className="font-bold text-muted">
            No administrators found.
          </p>
        ) : (
          <div className="space-y-3">
            {admins.map((admin) => (
              <div
                key={admin.id}
                className="flex flex-wrap items-center justify-between gap-3 border-2 border-black bg-surface p-4"
              >
                <div>
                  <p className="font-black">
                    {admin.name}
                  </p>

                  <p className="text-sm text-muted">
                    {admin.email}
                  </p>

                  <p className="mt-1 font-mono text-xs text-muted">
                    {admin.role?.toUpperCase()}
                  </p>
                </div>

                <span
                  className={`border-2 border-black px-3 py-1 text-xs font-black ${
                    admin.isActive
                      ? "bg-lime text-black"
                      : "bg-[#FF8A70] text-black"
                  }`}
                >
                  {admin.isActive ? "ACTIVE" : "DISABLED"}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}

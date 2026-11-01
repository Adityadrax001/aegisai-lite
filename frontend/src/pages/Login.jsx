
import { useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { ShieldCheck, LockKeyhole, Mail } from "lucide-react";
import { z } from "zod";

import useAuth from "../hooks/useAuth";

const loginSchema = z.object({
  email: z.email("Enter a valid email address"),
  password: z.string().min(1, "Password is required"),
});

export default function Login() {
  const navigate = useNavigate();
  const { login, isAuthenticated, loading } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg">
        <p className="font-mono font-bold">CHECKING SESSION...</p>
      </div>
    );
  }

  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    const parsed = loginSchema.safeParse({
      email: email.trim().toLowerCase(),
      password,
    });

    if (!parsed.success) {
      setError(parsed.error.issues[0].message);
      return;
    }

    try {
      setSubmitting(true);
      await login(parsed.data.email, parsed.data.password);
      navigate("/", { replace: true });
    } catch (err) {
      setError(err.message || "Login failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-bg px-4 py-10">
      <section className="w-full max-w-md border-2 border-black bg-surface p-7 shadow-[8px_8px_0px_#111] sm:p-9">
        <div className="mb-7 flex items-center gap-3">
          <div className="flex h-14 w-14 items-center justify-center border-2 border-black bg-lime">
            <ShieldCheck size={30} />
          </div>

          <div>
            <h1 className="text-2xl font-black tracking-tight">
              AEGISAI-LITE
            </h1>
            <p className="font-mono text-xs font-bold text-muted">
              SECURITY OPERATIONS CENTER
            </p>
          </div>
        </div>

        <div className="mb-7 border-l-4 border-black pl-4">
          <h2 className="text-3xl font-black">
            ADMIN LOGIN
          </h2>
          <p className="mt-1 text-sm text-muted">
            Authorized personnel only.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label
              htmlFor="admin-email"
              className="mb-2 block text-sm font-black"
            >
              EMAIL ADDRESS
            </label>

            <div className="relative">
              <Mail
                size={19}
                className="absolute left-3 top-1/2 -translate-y-1/2"
              />

              <input
                id="admin-email"
                type="email"
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full border-2 border-black bg-bg py-3 pl-11 pr-3 outline-none focus:ring-2 focus:ring-lime"
                placeholder="admin@example.com"
                required
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="admin-password"
              className="mb-2 block text-sm font-black"
            >
              PASSWORD
            </label>

            <div className="relative">
              <LockKeyhole
                size={19}
                className="absolute left-3 top-1/2 -translate-y-1/2"
              />

              <input
                id="admin-password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full border-2 border-black bg-bg py-3 pl-11 pr-3 outline-none focus:ring-2 focus:ring-lime"
                placeholder="Enter your password"
                required
              />
            </div>
          </div>

          {error && (
            <div
              role="alert"
              className="border-2 border-black bg-[#FFD5D0] p-3 text-sm font-bold text-black"
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full border-2 border-black bg-lime px-4 py-3 font-black text-black shadow-[4px_4px_0px_#111] transition-transform hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? "AUTHENTICATING..." : "SECURE LOGIN"}
          </button>
        </form>

        <p className="mt-7 text-center font-mono text-xs text-muted">
          SESSION PROTECTED BY JWT + REDIS
        </p>
      </section>
    </main>
  );
}

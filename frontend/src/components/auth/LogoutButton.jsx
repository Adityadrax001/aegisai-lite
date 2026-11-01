
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { LogOut } from "lucide-react";
import useAuth from "../../hooks/useAuth";

export default function LogoutButton() {
  const navigate = useNavigate();
  const { logout } = useAuth();

  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");

  async function handleLogout() {
    setPending(true);
    setError("");

    try {
      await logout();
      navigate("/login", { replace: true });
    } catch (err) {
      setError(err.message || "Logout failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <div>
      <button
        type="button"
        onClick={handleLogout}
        disabled={pending}
        className="flex w-full items-center justify-center gap-2 border-2 border-black bg-[#FF8A70] px-4 py-3 font-black text-black shadow-[3px_3px_0px_#111] disabled:opacity-60"
      >
        <LogOut size={18} />
        {pending ? "LOGGING OUT..." : "LOG OUT"}
      </button>

      {error && (
        <p role="alert" className="mt-2 text-xs font-bold text-red-700">
          {error}
        </p>
      )}
    </div>
  );
}

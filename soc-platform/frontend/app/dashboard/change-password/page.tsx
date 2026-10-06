"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { apiFetch, ApiError } from "@/lib/api";

export default function ChangePasswordPage() {
  const router = useRouter();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await apiFetch("/auth/change-password", {
        method: "POST",
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      });
      setDone(true);
      setTimeout(() => router.push("/dashboard"), 1000);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not change password");
    }
  }

  return (
    <div style={{ maxWidth: 380 }}>
      <div style={{ fontSize: 18, fontWeight: 600, marginBottom: 6 }}>Change your password</div>
      <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 20 }}>
        You're using the default bootstrap password - set your own before continuing.
      </div>
      <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <input
          type="password" placeholder="Current password" required
          value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)}
          style={inputStyle}
        />
        <input
          type="password" placeholder="New password" required minLength={8}
          value={newPassword} onChange={(e) => setNewPassword(e.target.value)}
          style={inputStyle}
        />
        {error && <div style={{ color: "var(--red)", fontSize: 12 }}>{error}</div>}
        {done && <div style={{ color: "var(--green)", fontSize: 12 }}>Password updated.</div>}
        <button type="submit" style={btnStyle}>Update password</button>
      </form>
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  padding: "8px 10px", background: "var(--raised)", border: "1px solid var(--border)",
  borderRadius: 5, color: "var(--text)", fontSize: 13, outline: "none",
};

const btnStyle: React.CSSProperties = {
  padding: "9px 16px", borderRadius: 6, border: "1px solid rgba(63,185,80,.3)",
  background: "rgba(63,185,80,.12)", color: "var(--green)", fontWeight: 600, cursor: "pointer", fontSize: 13,
};

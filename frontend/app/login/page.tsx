"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export default function LoginPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const res = await fetch("/api/v1/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      if (res.ok) {
        router.replace("/dashboard");
        router.refresh();
      } else {
        setError("Неверный пароль");
      }
    } catch {
      setError("Сеть недоступна, попробуй снова");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="center-form">
      <div className="logo" style={{ padding: 0, marginBottom: 16 }}>
        AETHER <em>MAIL</em>
      </div>
      <div className="card">
        <h1 style={{ fontSize: 18 }}>Вход в панель</h1>
        {error && <div className="msg err">{error}</div>}
        <form onSubmit={submit}>
          <input
            type="password"
            placeholder="Пароль администратора"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoFocus
          />
          <button className="btn" type="submit" disabled={busy} style={{ width: "100%" }}>
            {busy ? "Проверка…" : "Войти"}
          </button>
        </form>
      </div>
    </div>
  );
}

"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export default function MailboxManager({ mailboxes }: { mailboxes: string[] }) {
  const router = useRouter();
  const [local, setLocal] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  async function call(path: string, init: RequestInit, okText: string) {
    setBusy(true);
    setMessage(null);
    try {
      const res = await fetch(path, init);
      const body = await res.json().catch(() => ({}));
      if (res.ok) {
        setMessage({ ok: true, text: okText });
        setLocal("");
        setPassword("");
        router.refresh();
      } else {
        setMessage({ ok: false, text: `Ошибка: ${(body as { error?: string }).error ?? res.status}` });
      }
    } catch {
      setMessage({ ok: false, text: "Сетевая ошибка" });
    } finally {
      setBusy(false);
    }
  }

  function create(e: React.FormEvent) {
    e.preventDefault();
    void call(
      "/api/v1/mailboxes",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ local, password }),
      },
      "Ящик создан"
    );
  }

  function remove(email: string) {
    if (!confirm(`Удалить ящик ${email}?`)) return;
    void call(`/api/v1/mailboxes/${encodeURIComponent(email)}`, { method: "DELETE" }, "Ящик удалён");
  }

  return (
    <>
      <div className="card">
        <h2>Создать ящик</h2>
        {message && <div className={`msg ${message.ok ? "ok" : "err"}`}>{message.text}</div>}
        <form onSubmit={create}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <input
              placeholder="Имя ящика (например: info)"
              value={local}
              onChange={(e) => setLocal(e.target.value)}
              required
            />
            <input
              type="password"
              placeholder="Пароль (минимум 8 символов)"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
            />
          </div>
          <button className="btn" type="submit" disabled={busy}>
            Создать ящик
          </button>
        </form>
      </div>

      <div className="card">
        <h2>Существующие ящики</h2>
        {mailboxes.length === 0 ? (
          <p className="muted">Ящиков пока нет</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Адрес</th>
                <th style={{ width: 120 }}>Действие</th>
              </tr>
            </thead>
            <tbody>
              {mailboxes.map((m) => (
                <tr key={m}>
                  <td>{m}</td>
                  <td>
                    <button className="btn danger" onClick={() => remove(m)} disabled={busy}>
                      Удалить
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

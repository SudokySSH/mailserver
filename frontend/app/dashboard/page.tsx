import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import MailboxManager from "./mailbox-manager";
import LogoutButton from "./logout-button";

export const dynamic = "force-dynamic";

const API = process.env.API_INTERNAL ?? "http://api:8080";
const KEY = process.env.API_KEY ?? "";

async function fetchJSON(path: string): Promise<unknown> {
  const res = await fetch(`${API}${path}`, {
    headers: { "X-Api-Key": KEY },
    cache: "no-store",
  });
  if (!res.ok) return null;
  return res.json();
}

export default async function Dashboard() {
  if (!cookies().get("aether_session")?.value) {
    redirect("/login");
  }

  const [mailboxes, stats] = await Promise.all([
    fetchJSON("/v1/mailboxes"),
    fetch("http://audit-worker:8092/stats", { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .catch(() => null),
  ]);

  const boxes: string[] = Array.isArray(mailboxes) ? (mailboxes as string[]) : [];
  const statsObj = (stats ?? {}) as { total?: number; by_type?: Record<string, number> };

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="logo">
          AETHER <em>MAIL</em>
        </div>
        <a href="/dashboard" className="on">
          📧 Ящики
        </a>
        <a href="/dashboard#security">🛡 События безопасности</a>
        <a href="/legacy/" className="logout">
          ⚙ Старая панель
        </a>
        <LogoutButton />
      </aside>

      <main className="content">
        <h1>Панель управления</h1>

        <MailboxManager mailboxes={boxes} />

        <div className="card" id="security">
          <h2>События безопасности (агрегат от audit-worker, Java)</h2>
          {statsObj.total != null ? (
            <>
              <p className="muted" style={{ marginBottom: 10 }}>
                Всего событий: {statsObj.total}
              </p>
              <table>
                <thead>
                  <tr>
                    <th>Тип события</th>
                    <th>Количество</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(statsObj.by_type ?? {}).map(([type, count]) => (
                    <tr key={type}>
                      <td>
                        <code>{type}</code>
                      </td>
                      <td>{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : (
            <p className="muted">Статистика пока недоступна — воркер ещё не поднялся.</p>
          )}
        </div>
      </main>
    </div>
  );
}

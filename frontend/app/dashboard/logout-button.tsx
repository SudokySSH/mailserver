"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export default function LogoutButton() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);

  async function logout() {
    setBusy(true);
    try {
      await fetch("/api/v1/logout", { method: "POST" });
    } finally {
      router.replace("/login");
      router.refresh();
    }
  }

  return (
    <a
      href="#"
      className="logout"
      onClick={(e) => {
        e.preventDefault();
        void logout();
      }}
      style={{ opacity: busy ? 0.5 : 1 }}
    >
      ⎋ {busy ? "Выход…" : "Выйти"}
    </a>
  );
}

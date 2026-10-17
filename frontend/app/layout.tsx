import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AETHER MAIL",
  description: "Почтовый сервер — панель управления",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ru">
      <body>{children}</body>
    </html>
  );
}

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

export default function Home() {
  const hasSession = cookies().get("aether_session")?.value;
  redirect(hasSession ? "/dashboard" : "/login");
}

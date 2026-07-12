import { redirect } from "next/navigation";
import Landing from "@/components/landing/Landing";

// The front door. The analyst instrument lives at /console; legacy deep links
// that used to point at the root (?lens=…&day=…, ?offline=1, older ?demo/?view)
// are forwarded there so every documented capture recipe keeps working.
export default async function Home({
  searchParams,
}: {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}) {
  const sp = await searchParams;
  const legacy = ["lens", "day", "offline", "t", "view", "demo"];
  if (legacy.some((k) => sp[k] !== undefined)) {
    const qs = new URLSearchParams();
    for (const k of legacy) {
      const v = sp[k];
      if (typeof v === "string") qs.set(k, v);
    }
    redirect(`/console?${qs.toString()}`);
  }
  return <Landing />;
}

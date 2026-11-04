import { SentinelConsole } from "@/components/sentinel-console";

export default async function CatchAllPage({ params }: { params: Promise<{ slug?: string[] }> }) {
  const resolved = await params;
  return <SentinelConsole route={(resolved.slug ?? ["dashboard"]).join("/")} />;
}

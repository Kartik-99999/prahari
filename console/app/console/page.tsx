import ConsoleApp from "@/components/console/ConsoleApp";

// The analyst console — a clean, generic client over the PRAHARI BFF.
// It renders whatever incidents the running system reports (top-ranked by
// default, switchable), and shows an honest offline state when the stack is
// down. Deep links: ?incident=…&lens=story|graph|attack|path|events|response|audit&day=…
export default function ConsolePage() {
  return <ConsoleApp />;
}

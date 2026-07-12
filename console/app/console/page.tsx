import RedesignConsole from "@/components/redesign/RedesignConsole";

// The analyst console — the explorable five-lens instrument. Hydrates from the
// live BFF on mount (header badge says so honestly) and falls back to
// reconstructed INC-001 fixtures when the stack is down or ?offline=1.
export default function ConsolePage() {
  return <RedesignConsole />;
}

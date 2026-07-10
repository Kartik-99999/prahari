import RedesignConsole from "@/components/redesign/RedesignConsole";

// The console is the explorable-instrument redesign (ported from the approved
// Claude Design). It is self-contained — honest reconstructions of INC-001 as
// fixtures — so it renders without the BFF. The live-BFF components (Workspace,
// GraphView, CorrelatorStrip, …) remain in the tree for a wired variant.
export default function Home() {
  return <RedesignConsole />;
}

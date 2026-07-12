import type { Metadata } from "next";
import {
  Inter,
  JetBrains_Mono,
  Noto_Serif_Devanagari,
  Source_Serif_4,
} from "next/font/google";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains",
  subsets: ["latin"],
  display: "swap",
});

// Landing display face — calm, editorial serif (Tiempos-like), used big and light.
const sourceSerif = Source_Serif_4({
  variable: "--font-serif",
  subsets: ["latin"],
  display: "swap",
  weight: ["300", "400", "500", "600"],
});

// One word only: the etymology moment in the hero (प्रहरी).
const devanagari = Noto_Serif_Devanagari({
  variable: "--font-devanagari",
  subsets: ["devanagari"],
  weight: ["500", "600"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "PRAHARÍ — the breach that never happened",
  description:
    "AI cyber-resilience for critical national infrastructure: behavioural detection, graph correlation, auditable autonomy. Detection in hours, not months.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${jetbrainsMono.variable} ${sourceSerif.variable} ${devanagari.variable} h-full`}
    >
      <body className="min-h-full font-sans text-text">{children}</body>
    </html>
  );
}

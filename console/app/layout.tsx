import type { Metadata } from "next";
import {
  Fraunces,
  Inter,
  JetBrains_Mono,
  Noto_Serif_Devanagari,
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

// Landing display face — warm editorial serif, used big and sparingly.
const fraunces = Fraunces({
  variable: "--font-fraunces",
  subsets: ["latin"],
  display: "swap",
  axes: ["opsz"],
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
      className={`${inter.variable} ${jetbrainsMono.variable} ${fraunces.variable} ${devanagari.variable} h-full`}
    >
      <body className="min-h-full font-sans text-text">{children}</body>
    </html>
  );
}

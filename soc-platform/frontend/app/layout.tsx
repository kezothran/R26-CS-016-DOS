import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import Script from "next/script";
import "./globals.css";

// A real geometric sans + a proper monospace, in place of the OS default UI font - this one
// swap does more for "looks like a real product" than any individual widget, since every
// number and label on every page rides on it.
const inter = Inter({ subsets: ["latin"], variable: "--font-sans", display: "swap" });
const jetbrainsMono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono-face", display: "swap" });

export const metadata: Metadata = {
  title: "SENTRIX",
  description: "Cross-platform SOC dashboard for ICMP / UDP / SYN / fragmentation flood detection",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-attack="none" className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <head>
        {/* Applies a saved light-theme choice before first paint, so switching pages never
            flashes dark-then-light. Default (no stored value, or "dark") needs no action - the
            :root palette in globals.css is already dark. */}
        <Script id="soc-theme-init" strategy="beforeInteractive">
          {`try{if(localStorage.getItem("soc_theme")==="light"){document.documentElement.setAttribute("data-theme","light");}}catch(e){}`}
        </Script>
      </head>
      <body>{children}</body>
    </html>
  );
}

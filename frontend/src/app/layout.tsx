import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Security Center Dashboard",
  description: "Local antivirus evidence, compliance, and OCR review dashboard.",
};

// Keep the root layout server-renderable: browser-only preferences belong in
// page.tsx, where they are loaded after hydration.
export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full antialiased" suppressHydrationWarning>
      <body className="min-h-full flex flex-col" suppressHydrationWarning>{children}</body>
    </html>
  );
}

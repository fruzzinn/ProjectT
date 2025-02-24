import "./styles/globals.css";  // ✅ Correct path for the App Router

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-dark-bg text-light-text">{children}</body>
    </html>
  );
}

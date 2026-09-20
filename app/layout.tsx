import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import './globals.css';

const geistSans = Geist({
  variable: '--font-geist-sans',
  subsets: ['latin'],
});

const geistMono = Geist_Mono({
  variable: '--font-geist-mono',
  subsets: ['latin'],
});

export const metadata: Metadata = {
  metadataBase: new URL(
    process.env.NEXT_PUBLIC_SITE_URL || 'http://localhost:3000',
  ),
  title: 'HostCanvas — Yerel domain envanteri ve güvenlik izleme',
  description:
    'Ekipler için local-first domain envanteri, TLS/DNS/HTTP güvenlik kontrolleri ve incident takibi.',
  icons: {
    icon: [{ url: '/favicon.svg', type: 'image/svg+xml' }],
  },
  openGraph: {
    title: 'HostCanvas',
    description: 'Local-first domain inventory and security monitoring.',
    type: 'website',
    images: [{ url: '/og.png', width: 1200, height: 630, alt: 'HostCanvas' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'HostCanvas',
    description: 'Local-first domain inventory and security monitoring.',
    images: ['/og.png'],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="tr">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}

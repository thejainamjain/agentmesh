import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
    title: "AgentMesh Dashboard",
    description: "Real-time security monitoring for multi-agent AI systems",
};

export default function RootLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <html lang="en">
            <body>{children}</body>
        </html>
    );
}
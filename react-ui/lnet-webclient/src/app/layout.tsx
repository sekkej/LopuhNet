// app/layout.tsx
import { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Lopuh Client',
  description: 'Client for LopuhNet'
}

interface RootLayoutProps {
  children: React.ReactNode
}

export default function RootLayout({ children }: RootLayoutProps) {
  return (
    <html lang="en">
      <body>
        <div className="app-container">
          {children}
        </div>
      </body>
    </html>
  )
}

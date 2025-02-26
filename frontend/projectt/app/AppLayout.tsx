import React, { ReactNode, useState } from 'react';
import { motion } from 'framer-motion';
import { useRouter } from 'next/router';
import Link from 'next/link';

interface AppLayoutProps {
  children: ReactNode;
}

const AppLayout: React.FC<AppLayoutProps> = ({ children }) => {
  const router = useRouter();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  // Determine active route
  const isActive = (path: string) => {
    return router.pathname === path;
  };

  return (
    <div className="bg-dark-bg text-light-text min-h-screen flex flex-col">
      {/* Header */}
      <motion.header
        initial={{ y: -50, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.8 }}
        className="bg-dark-cyan w-full py-4 text-center font-bold shadow-md sticky top-0 z-50"
      >
        <div className="container mx-auto px-4 flex justify-between items-center">
          <h1 className="text-2xl">Cyber Threat Intelligence Platform</h1>
          <nav className="hidden md:block">
            <ul className="flex space-x-6">
              <li className={`cursor-pointer ${isActive('/') ? "text-white" : "text-gray-300 hover:text-white"}`}>
                <Link href="/">Dashboard</Link>
              </li>
              <li className={`cursor-pointer ${isActive('/threats') ? "text-white" : "text-gray-300 hover:text-white"}`}>
                <Link href="/threats">Threats</Link>
              </li>
              <li className={`cursor-pointer ${isActive('/phishing') ? "text-white" : "text-gray-300 hover:text-white"}`}>
                <Link href="/phishing">Phishing Detection</Link>
              </li>
              <li className={`cursor-pointer ${isActive('/actors') ? "text-white" : "text-gray-300 hover:text-white"}`}>
                <Link href="/actors">Threat Actors</Link>
              </li>
              <li className={`cursor-pointer ${isActive('/indicators') ? "text-white" : "text-gray-300 hover:text-white"}`}>
                <Link href="/indicators">IOCs</Link>
              </li>
            </ul>
          </nav>
          <div className="md:hidden">
            <button 
              className="text-white"
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
          </div>
        </div>
      </motion.header>

      {/* Mobile Menu */}
      {isMobileMenuOpen && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          exit={{ opacity: 0, height: 0 }}
          className="bg-gray-900 md:hidden"
        >
          <ul className="p-4">
            <li className={`py-2 ${isActive('/') ? "text-dark-cyan" : "text-white"}`}>
              <Link href="/">Dashboard</Link>
            </li>
            <li className={`py-2 ${isActive('/threats') ? "text-dark-cyan" : "text-white"}`}>
              <Link href="/threats">Threats</Link>
            </li>
            <li className={`py-2 ${isActive('/phishing') ? "text-dark-cyan" : "text-white"}`}>
              <Link href="/phishing">Phishing Detection</Link>
            </li>
            <li className={`py-2 ${isActive('/actors') ? "text-dark-cyan" : "text-white"}`}>
              <Link href="/actors">Threat Actors</Link>
            </li>
            <li className={`py-2 ${isActive('/indicators') ? "text-dark-cyan" : "text-white"}`}>
              <Link href="/indicators">IOCs</Link>
            </li>
          </ul>
        </motion.div>
      )}

      {/* Main content */}
      <main className="flex-grow">
        {children}
      </main>

      {/* Footer */}
      <footer className="bg-gray-900 text-center p-4 mt-auto">
        <div className="container mx-auto">
          <p className="text-gray-400">© {new Date().getFullYear()} Cyber Threat Intelligence Platform</p>
        </div>
      </footer>
    </div>
  );
};

export default AppLayout;
import React, { useState, useEffect } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Navbar } from './Navbar';

export const Layout: React.FC = () => {
  const navigate = useNavigate();

  const [menuLocation, setMenuLocation] = useState<string | null>(null);
  const location = useLocation();
  const menuOpen = menuLocation === location.key;
  const setMenuOpen = (open: boolean) => setMenuLocation(open ? location.key : null);
  useEffect(() => {
    const close = (event: KeyboardEvent) => { if (event.key === 'Escape') setMenuLocation(null); };
    window.addEventListener('keydown', close);
    return () => window.removeEventListener('keydown', close);
  }, []);
  return (
    <div className={`app-layout ${menuOpen ? 'menu-open' : ''}`}><a className="skip-link" href="#main-content">Skip to content</a>
      {menuOpen && <button className="nav-backdrop" aria-label="Close navigation" onClick={() => setMenuOpen(false)} />}
      <Sidebar />
      <div className="app-main">
        <Navbar menuOpen={menuOpen} onToggleMenu={() => setMenuOpen(!menuOpen)}
          onOpenScanModal={() => navigate('/scans')}
        />
        <main id="main-content" tabIndex={-1} className="app-content">
          <Outlet />
        </main>
      </div>



    </div>
  );
};
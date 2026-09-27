import { useState } from 'react';
import { Moon, Sun } from '@phosphor-icons/react';

export function ThemeToggle() {
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme || 'dark');
  function toggle() {
    const next = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    setTheme(next);
    try { localStorage.setItem('ecdat-theme', next); } catch { /* Still works when storage is unavailable. */ }
  }
  return <button type="button" className="btn btn-secondary theme-toggle" onClick={toggle}
    aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`} title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}>
    {theme === 'dark' ? <Sun size={19} /> : <Moon size={19} />}<span>{theme === 'dark' ? 'Light theme' : 'Dark theme'}</span>
  </button>;
}

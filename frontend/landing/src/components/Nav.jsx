import { useState, useEffect } from 'react';

export default function Nav() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 50);
    window.addEventListener('scroll', onScroll);
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <nav className="nav" style={{
      borderBottomColor: scrolled ? 'var(--border-strong)' : 'var(--border)',
    }}>
      <a href="/" className="nav-logo">
        <span className="nav-logo-text">Specula</span>
      </a>
      <ul className="nav-links">
        <li><a href="/dashboard" className="nav-cta">Launch App</a></li>
      </ul>
    </nav>
  );
}

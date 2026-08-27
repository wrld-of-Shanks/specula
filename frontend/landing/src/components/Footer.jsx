export default function Footer() {
  return (
    <footer className="footer">
      <div className="footer-inner">
        <div className="footer-brand">
          <svg width="20" height="20" viewBox="0 0 32 32" fill="none">
            <circle cx="16" cy="16" r="14" stroke="#d4f000" strokeWidth="1" opacity="0.4" />
            <circle cx="16" cy="16" r="2.5" fill="#d4f000" />
          </svg>
          <span className="footer-brand-text">Specula</span>
        </div>

        <div className="footer-copy">
          &copy; 2026 Specula Inc. All rights reserved.
        </div>

        <ul className="footer-links">
          <li><a href="/dashboard">Dashboard</a></li>
          <li><a href="#">Docs</a></li>
          <li><a href="#">GitHub</a></li>
          <li><a href="#">Status</a></li>
        </ul>
      </div>
    </footer>
  );
}

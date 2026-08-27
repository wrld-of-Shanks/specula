export default function Hero() {
  return (
    <section className="hero">
      <div className="hero-bg">
        <img src="/hero-bg.png" alt="Engraved eyes — the Eye of Horus sees all" />
      </div>
      <div className="hero-vignette" />
      <div className="hero-engraving-overlay" />

      <div className="hero-content">
        <div className="hero-eyebrow">AI Observability Platform</div>

        <h1 className="hero-headline">
          <span className="accent">Nothing</span> escapes<br />
          Specula.
        </h1>

        <p className="hero-sub">
          Meet <strong>Horus</strong> — the model that watches every token,
          correlates every signal, and understands what others miss.
          Full-spectrum AI intelligence, etched into every inference.
        </p>

        <div className="hero-actions">
          <a href="/dashboard" className="btn-secondary">
            See Horus in Action
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M5 12h14M12 5l7 7-7 7" />
            </svg>
          </a>
        </div>


      </div>
    </section>
  );
}

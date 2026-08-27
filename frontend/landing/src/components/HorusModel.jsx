import EyeOfHorus from './EyeOfHorus';

const capabilities = [
  {
    title: 'Multi-Modal Ingestion',
    desc: 'Text, code, embeddings, and structured outputs — all unified under one observation plane.',
    icon: (
      <svg viewBox="0 0 24 24">
        <rect x="3" y="3" width="7" height="7" />
        <rect x="14" y="3" width="7" height="7" />
        <rect x="3" y="14" width="7" height="7" />
        <rect x="14" y="14" width="7" height="7" />
      </svg>
    ),
  },
  {
    title: 'Temporal Reasoning',
    desc: 'Horus understands sequences, not snapshots. It reasons about how model behavior evolves across conversations.',
    icon: (
      <svg viewBox="0 0 24 24">
        <circle cx="12" cy="12" r="10" />
        <polyline points="12,6 12,12 16,14" />
      </svg>
    ),
  },
  {
    title: 'Threat Surface Mapping',
    desc: 'Automatically discovers and classifies potential failure modes across your entire inference pipeline.',
    icon: (
      <svg viewBox="0 0 24 24">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
  },
];

export default function HorusModel() {
  return (
    <section className="section horus" id="horus">
      <div className="section-inner">
        <div className="horus-layout">
          <div className="horus-visual">
            <div className="horus-eye">
              <EyeOfHorus className="horus-eye-svg" />
            </div>
          </div>

          <div className="horus-content">
            <div className="section-eyebrow">The Model</div>
            <h2 className="section-title">
              <span className="acid-text">Horus</span> sees what<br />you cannot.
            </h2>
            <p className="horus-desc">
              Named after the ancient eye that saw all, <strong>Horus</strong> is a
              purpose-built observation model trained on millions of failure modes,
              adversarial patterns, and emergent behaviors. It doesn&apos;t just
              monitor — it <strong>understands</strong>.
            </p>

            <div className="horus-capabilities">
              {capabilities.map((cap) => (
                <div className="horus-cap" key={cap.title}>
                  <div className="horus-cap-icon">{cap.icon}</div>
                  <div className="horus-cap-text">
                    <h4>{cap.title}</h4>
                    <p>{cap.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

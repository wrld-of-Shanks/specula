const features = [
  {
    num: '01',
    title: 'Token-Level Trace',
    desc: 'Every inference is traced from input to output. Token-by-token attribution reveals exactly where models reason, hallucinate, or stall.',
    icon: (
      <svg viewBox="0 0 24 24">
        <path d="M4 7h16M4 12h16M4 17h10" />
        <circle cx="20" cy="17" r="2" />
      </svg>
    ),
  },
  {
    num: '02',
    title: 'Anomaly Detection',
    desc: 'Horus identifies distributional drift, adversarial inputs, and emergent failure modes before they cascade into production incidents.',
    icon: (
      <svg viewBox="0 0 24 24">
        <path d="M12 2L2 22h20L12 2z" />
        <line x1="12" y1="9" x2="12" y2="15" />
        <circle cx="12" cy="18" r="0.5" fill="currentColor" />
      </svg>
    ),
  },
  {
    num: '03',
    title: 'Causal Correlation',
    desc: 'Goes beyond pattern matching. Horus builds causal graphs connecting prompts, model states, and outputs to find root causes, not just symptoms.',
    icon: (
      <svg viewBox="0 0 24 24">
        <circle cx="6" cy="6" r="3" />
        <circle cx="18" cy="18" r="3" />
        <circle cx="18" cy="6" r="3" />
        <line x1="8.5" y1="7.5" x2="15.5" y2="16.5" />
        <line x1="15.5" y1="7.5" x2="15.5" y2="15" />
      </svg>
    ),
  },
  {
    num: '04',
    title: 'Behavioral Fingerprinting',
    desc: 'Create unique behavioral signatures for each model deployment. Detect when a model drifts from its verified behavior profile.',
    icon: (
      <svg viewBox="0 0 24 24">
        <path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10 10-4.5 10-10" />
        <path d="M12 6c-3.3 0-6 2.7-6 6s2.7 6 6 6 6-2.7 6-6" />
        <circle cx="12" cy="12" r="2" />
      </svg>
    ),
  },
  {
    num: '05',
    title: 'Real-Time Stream Analysis',
    desc: 'Monitor live inference streams with sub-millisecond granularity. Catch anomalies the instant they appear, not after the fact.',
    icon: (
      <svg viewBox="0 0 24 24">
        <polyline points="22,6 13.5,14.5 8.5,9.5 2,16" />
        <polyline points="16,6 22,6 22,12" />
      </svg>
    ),
  },
  {
    num: '06',
    title: 'Audit-Grade Logging',
    desc: 'Every observation is cryptographically signed and immutable. Complete forensic trail for compliance, debugging, and model governance.',
    icon: (
      <svg viewBox="0 0 24 24">
        <rect x="3" y="3" width="18" height="18" rx="2" />
        <path d="M7 7h10M7 11h10M7 15h6" />
      </svg>
    ),
  },
];

export default function Features() {
  return (
    <section className="section" id="features">
      <div className="section-inner">
        <div className="section-eyebrow">Capabilities</div>
        <h2 className="section-title">
          See through the<br />black box.
        </h2>
        <p className="section-sub">
          Specula gives you total visibility into every layer of your AI stack —
          from raw tokens to strategic decisions.
        </p>
      </div>

      <div className="features-grid reg-marks reg-marks-extra">
        {features.map((f) => (
          <div className="feature-card" key={f.num}>
            <div className="feature-icon">{f.icon}</div>
            <div className="feature-number">{f.num}</div>
            <h3 className="feature-title">{f.title}</h3>
            <p className="feature-desc">{f.desc}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

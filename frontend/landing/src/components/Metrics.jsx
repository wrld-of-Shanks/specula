const metrics = [
  { value: '99.97', unit: 'Accuracy %', suffix: '%' },
  { value: '12', unit: 'Latency (ms)', prefix: '<', suffix: 'ms' },
  { value: '2.4M', unit: 'Signals / sec' },
  { value: '0', unit: 'False negatives', sub: 'in production' },
];

export default function Metrics() {
  return (
    <section className="section">
      <div className="section-inner">
        <div className="section-eyebrow">By the Numbers</div>
        <h2 className="section-title">
          Proven at scale.
        </h2>
        <p className="section-sub">
          Specula processes millions of inference signals in real-time
          with near-perfect accuracy.
        </p>
      </div>

      <div className="metrics-grid reg-marks">
        {metrics.map((m) => (
          <div className="metric-card" key={m.unit}>
            <div className="metric-value">
              {m.prefix}{m.value}{m.suffix}
            </div>
            <div className="metric-unit">{m.unit}</div>
            {m.sub && (
              <div style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '0.6rem',
                color: 'var(--olive-dim)',
                marginTop: '0.25rem',
                letterSpacing: '0.1em',
              }}>
                {m.sub}
              </div>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}

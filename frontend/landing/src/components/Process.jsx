const steps = [
  {
    num: '01',
    title: 'Connect',
    desc: 'One SDK line. Specula instruments your inference pipeline automatically — no model changes required.',
  },
  {
    num: '02',
    title: 'Observe',
    desc: 'Horus watches every token, every prompt, every output. Building a behavioral model of your system in real-time.',
  },
  {
    num: '03',
    title: 'Understand',
    desc: 'Get causal insights, not just dashboards. Know why things happen, not just that they did.',
  },
];

export default function Process() {
  return (
    <section className="section" id="process">
      <div className="section-inner">
        <div className="section-eyebrow">How It Works</div>
        <h2 className="section-title">
          Three steps to<br />total visibility.
        </h2>
        <p className="section-sub">
          From zero to omniscient in under five minutes.
        </p>

        <div className="process-steps">
          {steps.map((s) => (
            <div className="process-step" key={s.num}>
              <div className="process-step-num">
                <span>{s.num}</span>
              </div>
              <h3 className="process-step-title">{s.title}</h3>
              <p className="process-step-desc">{s.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

export default function Quote() {
  return (
    <section className="section quote-section">
      <div className="section-inner">
        <div className="quote-block reg-marks reg-marks-extra" style={{ padding: '3rem 2rem' }}>
          <div className="quote-mark">"</div>
          <p className="quote-text">
            Specula didn&apos;t just find our bugs — it showed us the shape of
            our blind spots. Horus caught a hallucination pattern that had
            evaded every other tool for months.
          </p>
          <div className="quote-author">
            <strong>Dr. Elena Vasquez</strong> — Head of AI Safety, Meridian Labs
          </div>
        </div>
      </div>
    </section>
  );
}

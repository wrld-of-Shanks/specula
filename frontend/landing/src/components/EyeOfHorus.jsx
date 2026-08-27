export default function EyeOfHorus({ className = '' }) {
  return (
    <svg
      viewBox="0 0 200 200"
      className={className}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      {/* Outer eye shape */}
      <path
        d="M100 40 C60 40, 20 70, 15 100 C20 130, 60 160, 100 160 C140 160, 180 130, 185 100 C180 70, 140 40, 100 40Z"
        stroke="#d4f000"
        strokeWidth="1.5"
        opacity="0.8"
      />
      {/* Inner iris */}
      <circle cx="100" cy="100" r="32" stroke="#d4f000" strokeWidth="1" opacity="0.6" />
      <circle cx="100" cy="100" r="20" stroke="#d4f000" strokeWidth="0.8" opacity="0.4" />
      {/* Pupil */}
      <circle cx="100" cy="100" r="10" fill="#d4f000" opacity="0.9" />
      <circle cx="100" cy="100" r="4" fill="#0a0d05" />
      {/* Highlight */}
      <circle cx="107" cy="93" r="3" fill="#d4f000" opacity="0.5" />
      {/* Horus teardrop */}
      <path
        d="M100 132 C100 132, 85 160, 80 180 C80 185, 88 188, 92 182 C96 176, 100 160, 100 132"
        stroke="#d4f000"
        strokeWidth="1.2"
        opacity="0.6"
      />
      {/* Eyebrow arch */}
      <path
        d="M30 70 C60 35, 140 35, 170 70"
        stroke="#d4f000"
        strokeWidth="0.8"
        opacity="0.3"
      />
      {/* Cross-hatch lines inside iris */}
      {[...Array(12)].map((_, i) => {
        const angle = (i * 30 * Math.PI) / 180;
        const x1 = 100 + 12 * Math.cos(angle);
        const y1 = 100 + 12 * Math.sin(angle);
        const x2 = 100 + 30 * Math.cos(angle);
        const y2 = 100 + 30 * Math.sin(angle);
        return (
          <line
            key={i}
            x1={x1}
            y1={y1}
            x2={x2}
            y2={y2}
            stroke="#d4f000"
            strokeWidth="0.3"
            opacity="0.25"
          />
        );
      })}
      {/* Spiral rays */}
      {[...Array(24)].map((_, i) => {
        const angle = (i * 15 * Math.PI) / 180;
        const x1 = 100 + 34 * Math.cos(angle);
        const y1 = 100 + 34 * Math.sin(angle);
        const x2 = 100 + 38 * Math.cos(angle);
        const y2 = 100 + 38 * Math.sin(angle);
        return (
          <line
            key={`r${i}`}
            x1={x1}
            y1={y1}
            x2={x2}
            y2={y2}
            stroke="#d4f000"
            strokeWidth="0.5"
            opacity="0.35"
          />
        );
      })}
    </svg>
  );
}

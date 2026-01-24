import React from 'react';

const HelpIcon = ({ size = 22 }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      xmlns="http://www.w3.org/2000/svg"
      style={{ display: 'inline-block', verticalAlign: 'middle' }}
    >
      {/* Head */}
      <circle cx="32" cy="16" r="12" fill="#E8EDF2" />
      <ellipse cx="32" cy="18" rx="9" ry="7" fill="#1F3564" />

      {/* Eyes */}
      <circle cx="28" cy="18" r="2.2" fill="#6EC6F0" />
      <circle cx="36" cy="18" r="2.2" fill="#6EC6F0" />

      {/* Antenna */}
      <rect x="29" y="2" width="6" height="6" rx="3" fill="#E8EDF2" />

      {/* Body */}
      <rect x="22" y="30" width="20" height="18" rx="6" fill="#E8EDF2" />
      <rect x="24" y="32" width="16" height="14" rx="5" fill="#D5DBE3" />

      {/* Left Arm */}
      <rect x="14" y="32" width="6" height="14" rx="3" fill="#1F3564" />
      <rect x="12" y="44" width="8" height="6" rx="3" fill="#E8EDF2" />

      {/* Right Arm (wave) */}
      <rect x="44" y="28" width="6" height="14" rx="3" fill="#1F3564" />
      <rect x="44" y="22" width="8" height="6" rx="3" fill="#E8EDF2" />

      {/* Legs */}
      <rect x="24" y="48" width="6" height="10" rx="3" fill="#1F3564" />
      <rect x="34" y="48" width="6" height="10" rx="3" fill="#1F3564" />

      {/* Feet */}
      <rect x="22" y="56" width="10" height="6" rx="3" fill="#E8EDF2" />
      <rect x="32" y="56" width="10" height="6" rx="3" fill="#E8EDF2" />
    </svg>
  );
};

export default HelpIcon;

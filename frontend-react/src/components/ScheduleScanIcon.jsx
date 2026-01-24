import React from 'react';

const ScheduleScanIcon = ({ size = 24 }) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      stroke="currentColor"
      strokeWidth="3"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{ display: 'inline-block', verticalAlign: 'middle' }}
    >
      {/* Clock circle */}
      <circle cx="24" cy="24" r="18" />

      {/* Hour hand */}
      <line x1="24" y1="24" x2="24" y2="14" />

      {/* Minute hand */}
      <line x1="24" y1="24" x2="32" y2="24" />
    </svg>
  );
};

export default ScheduleScanIcon;


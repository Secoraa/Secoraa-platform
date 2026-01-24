import React from 'react';

const ScanIcon = ({ size = 24 }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      style={{ display: 'inline-block', verticalAlign: 'middle' }}
      stroke="currentColor"
      strokeWidth="3"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {/* Top-left corner */}
      <path d="M6 14 V6 H14" />

      {/* Top-right corner */}
      <path d="M34 6 H42 V14" />

      {/* Bottom-right corner */}
      <path d="M42 34 V42 H34" />

      {/* Bottom-left corner */}
      <path d="M14 42 H6 V34" />

      {/* Center square */}
      <rect x="20" y="20" width="8" height="8" rx="1" />
    </svg>
  );
};

export default ScanIcon;

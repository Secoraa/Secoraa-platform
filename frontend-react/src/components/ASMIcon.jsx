import React from 'react';

const ASMIcon = ({ size = 16 }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      style={{ display: 'inline-block', verticalAlign: 'middle' }}
    >
      {/* Hexagon */}
      <polygon
        points="50 5, 90 27.5, 90 72.5, 50 95, 10 72.5, 10 27.5"
        fill="currentColor"
      />

      {/* ASM Text */}
      <text
        x="50"
        y="60"
        textAnchor="middle"
        fill="#ffffff"
        fontSize="36"
        fontWeight="700"
        fontFamily="Inter, Arial, Helvetica, sans-serif"
        letterSpacing="2"
      >
        ASM
      </text>
    </svg>
  );
};

export default ASMIcon;

import React from 'react';

const HelpIcon = ({ size = 20 }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
    xmlns="http://www.w3.org/2000/svg"
  >
    {/* Lifebuoy outer ring */}
    <circle cx="12" cy="12" r="10" />
    <circle cx="12" cy="12" r="4" />
    {/* Cross straps */}
    <line x1="14.83" y1="14.83" x2="19.07" y2="19.07" />
    <line x1="4.93" y1="19.07" x2="9.17" y2="14.83" />
    <line x1="14.83" y1="9.17" x2="19.07" y2="4.93" />
    <line x1="4.93" y1="4.93" x2="9.17" y2="9.17" />
  </svg>
);

export default HelpIcon;

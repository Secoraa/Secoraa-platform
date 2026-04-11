import React from 'react';

const ASMIcon = ({ size = 20 }) => (
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
    {/* Shield outline */}
    <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7l-9-5z" />
    {/* Network nodes inside the shield */}
    <circle cx="12" cy="9" r="1.5" fill="currentColor" stroke="none" />
    <circle cx="8.5" cy="14" r="1.5" fill="currentColor" stroke="none" />
    <circle cx="15.5" cy="14" r="1.5" fill="currentColor" stroke="none" />
    {/* Connecting lines */}
    <line x1="12" y1="10.5" x2="8.5" y2="12.5" />
    <line x1="12" y1="10.5" x2="15.5" y2="12.5" />
    <line x1="8.5" y1="14" x2="15.5" y2="14" />
  </svg>
);

export default ASMIcon;

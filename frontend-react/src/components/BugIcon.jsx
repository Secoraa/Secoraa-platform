import React from 'react';

const BugIcon = ({ size = 20 }) => (
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
    {/* Warning triangle */}
    <path d="M12 9l-3.5 6h7L12 9z" />
    {/* Exclamation */}
    <line x1="12" y1="11" x2="12" y2="13" strokeWidth="1.5" />
    <circle cx="12" cy="14.2" r="0.5" fill="currentColor" stroke="none" />
  </svg>
);

export default BugIcon;

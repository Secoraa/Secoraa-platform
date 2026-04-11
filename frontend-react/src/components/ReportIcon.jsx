import React from 'react';

const ReportIcon = ({ size = 20 }) => (
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
    {/* Clipboard outline */}
    <path d="M9 2h6v2H9V2z" />
    <path d="M7 4H5a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1h-2" />
    {/* Bar chart lines */}
    <line x1="8" y1="18" x2="8" y2="14" strokeWidth="2" />
    <line x1="12" y1="18" x2="12" y2="10" strokeWidth="2" />
    <line x1="16" y1="18" x2="16" y2="12" strokeWidth="2" />
  </svg>
);

export default ReportIcon;

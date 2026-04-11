import React from 'react';

const DashboardIcon = ({ size = 20 }) => (
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
    {/* Speedometer gauge arc */}
    <path d="M4.5 16.5a9 9 0 1 1 15 0" />
    {/* Gauge needle */}
    <line x1="12" y1="12" x2="15.5" y2="8.5" />
    <circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none" />
    {/* Tick marks */}
    <line x1="5" y1="12" x2="6.5" y2="12" />
    <line x1="12" y1="5" x2="12" y2="6.5" />
    <line x1="19" y1="12" x2="17.5" y2="12" />
    {/* Bottom line */}
    <line x1="7" y1="19" x2="17" y2="19" />
  </svg>
);

export default DashboardIcon;

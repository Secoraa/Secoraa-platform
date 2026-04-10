import React from 'react';

const AssetDiscoveryIcon = ({ size = 20 }) => (
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
    {/* Globe / network sphere */}
    <circle cx="11" cy="11" r="7" />
    <ellipse cx="11" cy="11" rx="3" ry="7" />
    <line x1="4" y1="11" x2="18" y2="11" />
    {/* Magnifying glass handle */}
    <line x1="16" y1="16" x2="21" y2="21" strokeWidth="2" />
  </svg>
);

export default AssetDiscoveryIcon;

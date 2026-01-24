import React from 'react';

const AssetDiscoveryIcon = ({ size = 20 }) => {
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
    >
      {/* Radar arcs */}
      <path d="M8 22a16 16 0 0 1 32 0" />
      <path d="M14 22a10 10 0 0 1 20 0" />
      <path d="M20 22a4 4 0 0 1 8 0" />

      {/* Scan base line */}
      <line x1="6" y1="24" x2="42" y2="24" />

      {/* Scan bars */}
      <line x1="10" y1="28" x2="10" y2="40" />
      <line x1="16" y1="28" x2="16" y2="36" />
      <line x1="22" y1="28" x2="22" y2="40" />
      <line x1="28" y1="28" x2="28" y2="36" />
      <line x1="34" y1="28" x2="34" y2="40" />
      <line x1="40" y1="28" x2="40" y2="36" />
    </svg>
  );
};

export default AssetDiscoveryIcon;


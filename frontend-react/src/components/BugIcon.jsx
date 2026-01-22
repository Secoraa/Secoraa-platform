import React from 'react';

const BugIcon = ({ size = 16 }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      style={{ display: 'inline-block', verticalAlign: 'middle' }}
    >
      {/* Bug body */}
      <ellipse cx="10" cy="10" rx="4" ry="5" stroke="currentColor" strokeWidth="1.2" fill="currentColor" />
      
      {/* Bug head */}
      <circle cx="10" cy="7" r="2.5" stroke="currentColor" strokeWidth="1.2" fill="currentColor" />
      
      {/* Antennae */}
      <line x1="10" y1="4.5" x2="8" y2="2" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="10" y1="4.5" x2="12" y2="2" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <circle cx="8" cy="2" r="0.8" fill="currentColor" />
      <circle cx="12" cy="2" r="0.8" fill="currentColor" />
      
      {/* Legs - left side */}
      <line x1="6" y1="9" x2="4" y2="8" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="6" y1="11" x2="4" y2="12" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="6" y1="13" x2="4" y2="14" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      
      {/* Legs - right side */}
      <line x1="14" y1="9" x2="16" y2="8" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="14" y1="11" x2="16" y2="12" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="14" y1="13" x2="16" y2="14" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      
      {/* Bug segments */}
      <line x1="10" y1="10" x2="10" y2="12" stroke="currentColor" strokeWidth="0.8" opacity="0.5" />
      <line x1="10" y1="12" x2="10" y2="14" stroke="currentColor" strokeWidth="0.8" opacity="0.5" />
    </svg>
  );
};

export default BugIcon;


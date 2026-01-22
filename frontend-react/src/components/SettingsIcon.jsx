import React from 'react';

const SettingsIcon = ({ size = 16 }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      style={{ display: 'inline-block', verticalAlign: 'middle' }}
    >
      {/* Gear shape */}
      <circle cx="10" cy="10" r="3.5" stroke="currentColor" strokeWidth="1.2" fill="none" />
      <circle cx="10" cy="10" r="1.2" stroke="currentColor" strokeWidth="1.2" fill="currentColor" />
      
      {/* Gear teeth - 8 teeth around the circle */}
      <line x1="10" y1="6.5" x2="10" y2="4.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="10" y1="13.5" x2="10" y2="15.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="6.5" y1="10" x2="4.5" y2="10" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="13.5" y1="10" x2="15.5" y2="10" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="7.76" y1="7.76" x2="6.34" y2="6.34" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="12.24" y1="12.24" x2="13.66" y2="13.66" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="12.24" y1="7.76" x2="13.66" y2="6.34" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="7.76" y1="12.24" x2="6.34" y2="13.66" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
    </svg>
  );
};

export default SettingsIcon;


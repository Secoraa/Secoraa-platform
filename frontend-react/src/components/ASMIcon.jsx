import React from 'react';

const ASMIcon = ({ size = 16 }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      style={{ display: 'inline-block', verticalAlign: 'middle' }}
    >
      {/* First Gear (left) */}
      <g>
        <circle cx="7" cy="10" r="3.5" stroke="currentColor" strokeWidth="1.2" fill="none" />
        <circle cx="7" cy="10" r="1.2" stroke="currentColor" strokeWidth="1.2" fill="none" />
        {/* Gear teeth - 8 teeth */}
        <line x1="7" y1="6.5" x2="7" y2="5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        <line x1="7" y1="13.5" x2="7" y2="15" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        <line x1="3.5" y1="10" x2="2" y2="10" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        <line x1="10.5" y1="10" x2="12" y2="10" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        <line x1="5.24" y1="6.76" x2="4.12" y2="5.64" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        <line x1="8.76" y1="13.24" x2="9.88" y2="14.36" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        <line x1="8.76" y1="6.76" x2="9.88" y2="5.64" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        <line x1="5.24" y1="13.24" x2="4.12" y2="14.36" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      </g>
      
      {/* Second Gear (right, overlapping) */}
      <g>
        <circle cx="13" cy="10" r="3.5" stroke="currentColor" strokeWidth="1.2" fill="none" />
        <circle cx="13" cy="10" r="1.2" stroke="currentColor" strokeWidth="1.2" fill="none" />
        {/* Gear teeth - 8 teeth */}
        <line x1="13" y1="6.5" x2="13" y2="5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        <line x1="13" y1="13.5" x2="13" y2="15" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        <line x1="9.5" y1="10" x2="8" y2="10" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        <line x1="16.5" y1="10" x2="18" y2="10" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        <line x1="11.24" y1="6.76" x2="10.12" y2="5.64" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        <line x1="14.76" y1="13.24" x2="15.88" y2="14.36" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        <line x1="14.76" y1="6.76" x2="15.88" y2="5.64" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        <line x1="11.24" y1="13.24" x2="10.12" y2="14.36" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      </g>
    </svg>
  );
};

export default ASMIcon;

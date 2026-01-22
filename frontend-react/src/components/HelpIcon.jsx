import React from 'react';

const HelpIcon = ({ size = 22 }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      style={{ display: 'inline-block', verticalAlign: 'middle' }}
      color="currentColor"
    >
      {/* Person's head */}
      <circle cx="10" cy="7" r="3" stroke="currentColor" strokeWidth="1.2" fill="currentColor" />
      
      {/* Headset band */}
      <path
        d="M6.5 6.5 C6.5 5.5 7.5 4.5 8.5 4.5 L11.5 4.5 C12.5 4.5 13.5 5.5 13.5 6.5"
        stroke="currentColor"
        strokeWidth="1.2"
        fill="none"
        strokeLinecap="round"
      />
      
      {/* Left earpiece */}
      <circle cx="6.5" cy="6.5" r="1.2" stroke="currentColor" strokeWidth="1.2" fill="currentColor" />
      
      {/* Right earpiece */}
      <circle cx="13.5" cy="6.5" r="1.2" stroke="currentColor" strokeWidth="1.2" fill="currentColor" />
      
      {/* Microphone boom */}
      <line x1="13.5" y1="6.5" x2="15" y2="9" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <circle cx="15" cy="9.5" r="0.8" fill="currentColor" />
      
      {/* Body/Torso */}
      <rect x="7" y="10" width="6" height="5" rx="1" stroke="currentColor" strokeWidth="1.2" fill="currentColor" />
      
      {/* Question mark circle (help symbol) */}
      <circle cx="10" cy="5" r="1.8" stroke="currentColor" strokeWidth="1" fill="none" />
      <path
        d="M10 3.2 Q10 2.8 9.6 2.8 Q9.2 2.8 9.2 3.2"
        stroke="currentColor"
        strokeWidth="1"
        fill="none"
        strokeLinecap="round"
      />
      <line x1="10" y1="4.2" x2="10" y2="4.8" stroke="currentColor" strokeWidth="1" strokeLinecap="round" />
    </svg>
  );
};

export default HelpIcon;

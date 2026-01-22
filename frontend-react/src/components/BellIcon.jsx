import React from 'react';

const BellIcon = ({ size = 24 }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      style={{ display: 'inline-block', verticalAlign: 'middle' }}
      color="currentColor"
    >
      {/* Bell body - more detailed */}
      <path
        d="M12 2C10.5 2 9 3 9 4.5V8C9 9.5 8.5 11 7.5 12.5V15C7.5 15.5 8 16 8.5 16H15.5C16 16 16.5 15.5 16.5 15V12.5C15.5 11 15 9.5 15 8V4.5C15 3 13.5 2 12 2Z"
        stroke="currentColor"
        strokeWidth="1.5"
        fill="currentColor"
      />
      
      {/* Bell top handle */}
      <path
        d="M10 2L12 1L14 2"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        fill="none"
      />
      
      {/* Bell clapper */}
      <circle cx="12" cy="12.5" r="1" fill="currentColor" />
      <line x1="12" y1="13.5" x2="12" y2="16" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <circle cx="12" cy="16.5" r="0.8" fill="currentColor" />
      
      {/* Bell rim details */}
      <line x1="9" y1="9" x2="15" y2="9" stroke="currentColor" strokeWidth="1" opacity="0.7" />
      <line x1="9.5" y1="10.5" x2="14.5" y2="10.5" stroke="currentColor" strokeWidth="1" opacity="0.7" />
    </svg>
  );
};

export default BellIcon;

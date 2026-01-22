import React from 'react';

const ReportIcon = ({ size = 16 }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      style={{ display: 'inline-block', verticalAlign: 'middle' }}
    >
      {/* Document/Report shape */}
      <path
        d="M5 2C4.44772 2 4 2.44772 4 3V17C4 17.5523 4.44772 18 5 18H15C15.5523 18 16 17.5523 16 17V6L11 1H5Z"
        stroke="currentColor"
        strokeWidth="1.2"
        fill="none"
      />
      {/* Folded corner */}
      <path
        d="M11 1V6H16"
        stroke="currentColor"
        strokeWidth="1.2"
        fill="none"
      />
      {/* Lines on document */}
      <line x1="7" y1="9" x2="13" y2="9" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="7" y1="12" x2="13" y2="12" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="7" y1="15" x2="11" y2="15" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
    </svg>
  );
};

export default ReportIcon;


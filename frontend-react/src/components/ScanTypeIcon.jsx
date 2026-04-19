import React from 'react';

const ScanTypeIcon = ({ type, size = 18 }) => {
  const common = {
    width: size,
    height: size,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.8,
    strokeLinecap: 'round',
    strokeLinejoin: 'round',
    xmlns: 'http://www.w3.org/2000/svg',
  };
  switch (type) {
    case 'dd':
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="9" />
          <path d="M3 12h18" />
          <path d="M12 3a14 14 0 0 1 0 18" />
          <path d="M12 3a14 14 0 0 0 0 18" />
        </svg>
      );
    case 'api':
      return (
        <svg {...common}>
          <path d="M10 13a5 5 0 0 0 7.07 0l3-3a5 5 0 1 0-7.07-7.07L11.5 4.5" />
          <path d="M14 11a5 5 0 0 0-7.07 0l-3 3a5 5 0 1 0 7.07 7.07L12.5 19.5" />
        </svg>
      );
    case 'subdomain':
    case 'web':
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="9" />
          <path d="M3 12h18" />
          <path d="M12 3a14 14 0 0 1 0 18" />
          <path d="M12 3a14 14 0 0 0 0 18" />
        </svg>
      );
    case 'vulnerability':
      return (
        <svg {...common}>
          <path d="M12 2.5l8 3v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10v-6l8-3z" />
          <path d="M9.5 12l2 2 3.5-4" />
        </svg>
      );
    case 'network':
      return (
        <svg {...common}>
          <path d="M2 12a15 15 0 0 1 20 0" />
          <path d="M5 15a10 10 0 0 1 14 0" />
          <path d="M8.5 18a5 5 0 0 1 7 0" />
          <circle cx="12" cy="20.5" r="1" fill="currentColor" stroke="none" />
        </svg>
      );
    case 'ci_api_security':
    case 'ci_subdomain':
      return (
        <svg {...common}>
          <circle cx="6" cy="5" r="2.2" />
          <circle cx="6" cy="19" r="2.2" />
          <circle cx="18" cy="12" r="2.2" />
          <path d="M6 7.2v9.6" />
          <path d="M6 12h6a4 4 0 0 0 4-4" />
        </svg>
      );
    default:
      return null;
  }
};

export default ScanTypeIcon;

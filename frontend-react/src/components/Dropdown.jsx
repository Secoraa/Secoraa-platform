import React, { useEffect, useRef, useState } from 'react';
import './Dropdown.css';

const Dropdown = ({
  value,
  onChange,
  options,
  placeholder = 'Select',
  disabled = false,
  className = '',
}) => {
  const [open, setOpen] = useState(false);
  const rootRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const handleClickOutside = (event) => {
      if (rootRef.current && !rootRef.current.contains(event.target)) {
        setOpen(false);
      }
    };
    const handleKey = (event) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKey);
    };
  }, [open]);

  const selected = options.find((o) => String(o.value) === String(value));
  const rootClass = [
    'gold-dropdown',
    open ? 'is-open' : '',
    disabled ? 'is-disabled' : '',
    className,
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <div className={rootClass} ref={rootRef}>
      <button
        type="button"
        className="gold-dropdown__trigger"
        aria-haspopup="listbox"
        aria-expanded={open}
        disabled={disabled}
        onClick={() => !disabled && setOpen((v) => !v)}
      >
        <span className="gold-dropdown__selected">
          {selected?.icon && (
            <span className="gold-dropdown__icon">{selected.icon}</span>
          )}
          <span
            className={`gold-dropdown__label${selected ? '' : ' is-placeholder'}`}
          >
            {selected ? selected.label : placeholder}
          </span>
        </span>
        <svg
          className="gold-dropdown__chevron"
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>
      {open && (
        <ul className="gold-dropdown__menu" role="listbox">
          {options.length === 0 && (
            <li className="gold-dropdown__empty">No options</li>
          )}
          {options.map((option) => {
            const isSelected = String(option.value) === String(value);
            return (
              <li
                key={String(option.value)}
                role="option"
                aria-selected={isSelected}
                className={`gold-dropdown__option${isSelected ? ' is-selected' : ''}${option.disabled ? ' is-disabled' : ''}`}
                onClick={() => {
                  if (option.disabled) return;
                  onChange(option.value);
                  setOpen(false);
                }}
              >
                {option.icon && (
                  <span className="gold-dropdown__icon">{option.icon}</span>
                )}
                <span className="gold-dropdown__label">{option.label}</span>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
};

export default Dropdown;

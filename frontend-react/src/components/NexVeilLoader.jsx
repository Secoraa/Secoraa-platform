import React, { useEffect, useRef, useState } from 'react';
import './NexVeilLoader.css';

const MESSAGES = [
  ["Hold tight, we're on it", "YOUR SECURITY REPORT IS BEING FORGED..."],
  ["Almost cracked it - legally", "RUNNING THE FINAL CHECKS..."],
  ["Good things take a sec", "HUNTING DOWN EVERY VULNERABILITY..."],
  ["Patience, hacker mode on", "DEEP SCANNING YOUR ATTACK SURFACE..."],
  ["We're faster than the threats", "LOCKING IN YOUR FINDINGS..."],
  ["Nearly there, stay with us", "WRAPPING UP THE ANALYSIS..."],
];

const NexVeilLoader = ({ message }) => {
  const [msgIdx, setMsgIdx] = useState(0);
  const sceneRef = useRef(null);

  // Rotate messages
  useEffect(() => {
    if (message) return; // skip rotation if custom message provided
    const interval = setInterval(() => {
      setMsgIdx((prev) => (prev + 1) % MESSAGES.length);
    }, 2400);
    return () => clearInterval(interval);
  }, [message]);

  // Spawn particles
  useEffect(() => {
    const scene = sceneRef.current;
    if (!scene) return;
    const interval = setInterval(() => {
      const p = document.createElement('div');
      p.className = 'nv-particle';
      p.style.left = Math.random() * 100 + '%';
      p.style.bottom = (Math.random() * 40 + 5) + '%';
      const dur = (Math.random() * 3 + 2).toFixed(1);
      const delay = (Math.random() * 1.5).toFixed(1);
      p.style.animationDuration = dur + 's';
      p.style.animationDelay = delay + 's';
      scene.appendChild(p);
      setTimeout(() => { if (p.parentNode) p.remove(); }, (parseFloat(dur) + parseFloat(delay)) * 1000 + 200);
    }, 450);
    return () => clearInterval(interval);
  }, []);

  const [mainText, subText] = message
    ? [message, '']
    : MESSAGES[msgIdx];

  return (
    <div className="nv-loader-page" ref={sceneRef}>
      <div className="nv-grid-bg"></div>
      <div className="nv-hud-h"></div>
      <div className="nv-hud-v"></div>
      <div className="nv-corner nv-corner-tl"></div>
      <div className="nv-corner nv-corner-tr"></div>
      <div className="nv-corner nv-corner-bl"></div>
      <div className="nv-corner nv-corner-br"></div>

      <div className="nv-loader-center">
        <div className="nv-hex-wrapper">
          <div className="nv-hex-ring">
            <svg className="nv-hex-svg" viewBox="0 0 130 130" fill="none">
              <polygon points="65,4 121,34 121,96 65,126 9,96 9,34" stroke="#D4A017" strokeWidth="1.2" strokeOpacity="0.9" fill="none"/>
            </svg>
          </div>
          <div className="nv-hex-ring nv-hex-ring-2">
            <svg className="nv-hex-svg" viewBox="0 0 130 130" fill="none">
              <polygon points="65,16 107,40 107,90 65,114 23,90 23,40" stroke="#B8860B" strokeWidth="0.8" strokeOpacity="0.55" fill="none"/>
            </svg>
          </div>
          <div className="nv-hex-ring nv-hex-ring-3">
            <svg className="nv-hex-svg" viewBox="0 0 130 130" fill="none">
              <polygon points="65,28 95,46 95,84 65,102 35,84 35,46" stroke="#D4A017" strokeWidth="0.5" strokeOpacity="0.3" fill="none"/>
            </svg>
          </div>
          <div className="nv-orbit-ring nv-orbit-ring-1"></div>
          <div className="nv-orbit-ring nv-orbit-ring-2"></div>
          <div className="nv-core">
            <svg width="38" height="38" viewBox="0 0 38 38" fill="none">
              <polygon points="19,2 35,11 35,27 19,36 3,27 3,11" fill="rgba(212,160,23,0.12)" stroke="#D4A017" strokeWidth="1.5"/>
              <text x="19" y="24" textAnchor="middle" fontSize="11" fontWeight="700" fill="#D4A017" fontFamily="Rajdhani,sans-serif" letterSpacing="1">NV</text>
            </svg>
          </div>
        </div>

        <div className="nv-text-block">
          <div className="nv-brand">NexVeil Security</div>
          <div className="nv-main-msg"><span key={msgIdx + mainText}>{mainText}</span></div>
          {subText && <div className="nv-sub-msg"><span key={msgIdx + subText}>{subText}</span></div>}
        </div>

        <div className="nv-scan-wrap">
          <div className="nv-scan-bar"><div className="nv-scan-glow"></div></div>
          <div className="nv-scan-labels">
            <span>INITIALIZING</span><span>SYS CHECK</span><span>READY</span>
          </div>
        </div>

        <div className="nv-dots">
          <div className="nv-dot"></div>
          <div className="nv-dot"></div>
          <div className="nv-dot"></div>
        </div>
      </div>
    </div>
  );
};

export default NexVeilLoader;

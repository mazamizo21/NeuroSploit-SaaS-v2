"use client";

import React, { useId } from 'react';
import { motion } from 'framer-motion';

export const AnimatedLogo: React.FC = () => {
    return (
        <div className="relative group cursor-pointer flex items-center justify-center p-2 isolate">
            {/* Glitch Effect Layers (cloned SVG) */}
            <motion.div
                className="absolute inset-0 opacity-0 group-hover:opacity-100 mix-blend-screen will-change-transform"
                animate={{
                    x: [0, -2, 2, -1, 1, 0],
                    y: [0, 1, -1, 0],
                }}
                transition={{
                    repeat: Infinity,
                    duration: 0.2,
                    repeatDelay: 2,
                }}
            >
                <LogoSVG opacity={0.3} />
            </motion.div>

            <motion.div
                className="absolute inset-0 opacity-0 group-hover:opacity-100 mix-blend-plus-lighter will-change-transform"
                animate={{
                    x: [0, 2, -2, 1, -1, 0],
                    y: [0, -1, 1, 0],
                }}
                transition={{
                    repeat: Infinity,
                    duration: 0.3,
                    repeatDelay: 3,
                }}
            >
                <LogoSVG opacity={0.3} hueRotate={180} />
            </motion.div>

            {/* Main Logo */}
            <motion.div
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="relative z-10 will-change-transform"
            >
                <LogoSVG />
            </motion.div>

            {/* Scanline overlay */}
            <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(transparent_50%,rgba(0,0,0,0.5)_50%)] bg-[length:100%_4px] opacity-10" />
        </div>
    );
};

const LogoSVG = ({ opacity = 1, hueRotate = 0 }: { opacity?: number; hueRotate?: number }) => {
    const id = useId();
    const gradientId = `neon-gradient-${id.replace(/:/g, "")}`;
    const glowId = `neon-glow-${id.replace(/:/g, "")}`;

    return (
        <svg
            width="200"
            height="60"
            viewBox="0 0 200 60"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
            style={{
                opacity,
                filter: hueRotate ? `hue-rotate(${hueRotate}deg)` : 'drop-shadow(0 0 8px rgba(176,38,255,0.3))'
            }}
        >
            <defs>
                <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="50%">
                    <stop offset="0%" stopColor="#d946ef" /> {/* Fuchsia-500 */}
                    <stop offset="50%" stopColor="#8b5cf6" /> {/* Violet-500 */}
                    <stop offset="100%" stopColor="#3b82f6" /> {/* Blue-500 */}
                </linearGradient>
                <filter id={glowId} x="-50%" y="-50%" width="200%" height="200%">
                    <feGaussianBlur stdDeviation="2" result="coloredBlur" />
                    <feMerge>
                        <feMergeNode in="coloredBlur" />
                        <feMergeNode in="SourceGraphic" />
                    </feMerge>
                </filter>
            </defs>

            {/* Abstract Cyber Shield Icon */}
            <g transform="translate(10, 10)">
                <path
                    d="M15 0 L30 8 V20 C30 30 24 38 15 42 C6 38 0 30 0 20 V8 L15 0Z"
                    fill="none"
                    stroke={`url(#${gradientId})`}
                    strokeWidth="2"
                    style={{ filter: `drop-shadow(0 0 4px rgba(139, 92, 246, 0.5))` }}
                />
                {/* Inner tech geometric details */}
                <path d="M15 8 L15 34" stroke="#8b5cf6" strokeWidth="1.5" strokeLinecap="round" />
                <path d="M8 20 L22 20" stroke="#8b5cf6" strokeWidth="1.5" strokeLinecap="round" />
                <circle cx="15" cy="20" r="3" fill="#fff" style={{ filter: `drop-shadow(0 0 4px rgba(255, 255, 255, 0.8))` }} />
                <circle cx="15" cy="20" r="8" stroke="#3b82f6" strokeWidth="1" strokeDasharray="2 2" />
            </g>

            {/* Text Group */}
            <g transform="translate(50, 38)">
                <text
                    fontFamily="'JetBrains Mono', 'Fira Code', monospace"
                    fontSize="26"
                    fontWeight="800"
                    letterSpacing="-1"
                    fill={`url(#${gradientId})`}
                    style={{ filter: `drop-shadow(0 0 4px rgba(139, 92, 246, 0.5))` }}
                >
                    TAZO
                </text>
                <text
                    x="68"
                    fontFamily="'JetBrains Mono', 'Fira Code', monospace"
                    fontSize="26"
                    fontWeight="700"
                    letterSpacing="-1"
                    fill="#ffffff"
                >
                    SPLOIT
                </text>
            </g>

            {/* VIP Badge - stamped style */}
            <g transform="translate(160, 5)">
                <rect
                    x="0"
                    y="0"
                    width="36"
                    height="18"
                    rx="4"
                    fill="#facc15"
                    fillOpacity="0.1"
                    stroke="#facc15"
                    strokeWidth="1.5"
                />
                <text
                    x="18"
                    y="13"
                    fontFamily="sans-serif"
                    fontSize="10"
                    fontWeight="900"
                    fill="#facc15"
                    textAnchor="middle"
                    style={{ textShadow: "0 0 4px rgba(250, 204, 21, 0.6)" }}
                >
                    VIP
                </text>
            </g>
        </svg>
    );
};

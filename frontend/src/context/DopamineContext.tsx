"use client";

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import confetti from 'canvas-confetti';

interface DopamineContextType {
    score: number;
    combo: number;
    addScore: (points: number) => void;
    triggerCriticalFinding: () => void;
    triggerSuccess: () => void;
    triggerWarning: () => void;
    playSound: (type: 'success' | 'alert' | 'click') => void;
}

const DopamineContext = createContext<DopamineContextType | undefined>(undefined);

export const useDopamine = () => {
    const context = useContext(DopamineContext);
    if (!context) {
        throw new Error('useDopamine must be used within a DopamineProvider');
    }
    return context;
};

interface DopamineProviderProps {
    children: ReactNode;
}

export const DopamineProvider: React.FC<DopamineProviderProps> = ({ children }) => {
    const [score, setScore] = useState(0);
    const [combo, setCombo] = useState(0);
    const [audioEnabled, setAudioEnabled] = useState(true);

    // Reset combo after inactivity
    useEffect(() => {
        if (combo > 0) {
            const timer = setTimeout(() => setCombo(0), 5000);
            return () => clearTimeout(timer);
        }
    }, [combo]);

    const playSound = (type: 'success' | 'alert' | 'click') => {
        if (!audioEnabled) return;
        // In a real app, we would load and play actual audio files here
        // For now, we'll just log or use browser APIs if needed, but keeping it simple
        // to avoid missing asset errors.
        // console.log(`Playing sound: ${type}`);
    };

    const addScore = (points: number) => {
        setScore(prev => prev + points + (combo * 10));
        setCombo(prev => prev + 1);
    };

    const triggerCriticalFinding = () => {
        playSound('alert');
        // Intense red/orange confetti
        const duration = 3000;
        const animationEnd = Date.now() + duration;
        const defaults = { startVelocity: 30, spread: 360, ticks: 60, zIndex: 0 };

        const randomInRange = (min: number, max: number) => Math.random() * (max - min) + min;

        const interval: any = setInterval(function () {
            const timeLeft = animationEnd - Date.now();

            if (timeLeft <= 0) {
                return clearInterval(interval);
            }

            const particleCount = 50 * (timeLeft / duration);
            confetti({
                ...defaults,
                particleCount,
                origin: { x: randomInRange(0.1, 0.3), y: Math.random() - 0.2 },
                colors: ['#ef4444', '#f97316', '#000000']
            });
            confetti({
                ...defaults,
                particleCount,
                origin: { x: randomInRange(0.7, 0.9), y: Math.random() - 0.2 },
                colors: ['#ef4444', '#f97316', '#000000']
            });
        }, 250);

        addScore(500);
    };

    const triggerSuccess = () => {
        playSound('success');
        confetti({
            particleCount: 100,
            spread: 70,
            origin: { y: 0.6 },
            colors: ['#22c55e', '#00ff41', '#ffffff']
        });
        addScore(100);
    };

    const triggerWarning = () => {
        playSound('alert');
        // Shake effect is handled by CSS classes applied to elements, 
        // but we can add global visual cues here if needed.
        addScore(50);
    };

    return (
        <DopamineContext.Provider value={{
            score,
            combo,
            addScore,
            triggerCriticalFinding,
            triggerSuccess,
            triggerWarning,
            playSound
        }}>
            {children}
        </DopamineContext.Provider>
    );
};

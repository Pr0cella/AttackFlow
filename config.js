/**
 * Kill Chain Visualizer Configuration
 * 
 * Central configuration file for colors, settings, and other parameters.
 * Import this file in HTML pages to use consistent theming.
 */

const CONFIG = {
    // Application info
    version: '2.4.2',
    changelogUrl: 'CHANGELOG.md',
    
    // Phase colors (IN/THROUGH/OUT) - distinct from framework colors
    phases: {
        in: '#10b981',       // Emerald green - entry/initial foothold
        through: '#06b6d4',  // Cyan - movement/propagation
        out: '#ef4444'       // Red - impact/action on objectives
    },
    
    // Framework colors (ATT&CK/CAPEC/CWE)
    frameworks: {
        attack: '#3b82f6',   // Blue
        capec: '#8b5cf6',    // Purple
        cwe: '#f59e0b'       // Orange
    },
    
    // UI colors
    ui: {
        bgDark: '#1a1a1a',
        bgCard: '#242424',
        bgPhase: '#2d2d2d',
        textPrimary: '#e5e5e5',
        textSecondary: '#a3a3a3',
        borderColor: '#404040',
        accent: '#71717a'
    },
    
    // Future config placeholders
    display: {
        maxNameLength: 200,      // Max width for entity names in tags
        maxDescLength: 800,      // Max description length in detail panel
        maxMitigations: 8,       // Max mitigations to show
        maxReferences: 3         // Max references to show
    }
};

// Apply config colors to CSS variables
function applyConfigColors() {
    const root = document.documentElement;
    
    // Phase colors
    root.style.setProperty('--phase-in', CONFIG.phases.in);
    root.style.setProperty('--phase-through', CONFIG.phases.through);
    root.style.setProperty('--phase-out', CONFIG.phases.out);
    
    // Framework colors
    root.style.setProperty('--attack-color', CONFIG.frameworks.attack);
    root.style.setProperty('--capec-color', CONFIG.frameworks.capec);
    root.style.setProperty('--cwe-color', CONFIG.frameworks.cwe);
    
    // UI colors
    root.style.setProperty('--bg-dark', CONFIG.ui.bgDark);
    root.style.setProperty('--bg-card', CONFIG.ui.bgCard);
    root.style.setProperty('--bg-phase', CONFIG.ui.bgPhase);
    root.style.setProperty('--text-primary', CONFIG.ui.textPrimary);
    root.style.setProperty('--text-secondary', CONFIG.ui.textSecondary);
    root.style.setProperty('--border-color', CONFIG.ui.borderColor);
    root.style.setProperty('--accent', CONFIG.ui.accent);
}

// Export for module usage (if needed)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { CONFIG, applyConfigColors };
}

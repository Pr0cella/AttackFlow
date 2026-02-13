/**
 * Kill Chain Visualizer Configuration
 * 
 * Central configuration file for colors, settings, and other parameters.
 * Import this file in HTML pages to use consistent theming.
 */

const CONFIG = {
    // Application info
    version: '2.7.1',
    changelogUrl: 'CHANGELOG.md',
    
    // Framework source files (for extraction scripts)
    sources: {
        // CAPEC XML files
        capec: {
            domains: 'frameworks/CAPEC/DOMAINS.xml',
            mechanisms: 'frameworks/CAPEC/MECHANISMS.xml'
        },
        // CWE XML files
        cwe: {
            hardware: 'frameworks/CWE/HARDWARE.xml',
            software: 'frameworks/CWE/SOFTWARE.xml',
            all: 'frameworks/CWE/ALL.xml'
        },
        // ATT&CK STIX bundles (v18.1 as of 01/2026)
        attack: {
            version: '18.1',
            enterprise: 'frameworks/ATTCK/ENTERPRISE.json',
            mobile: 'frameworks/ATTCK/MOBILE.json',
            ics: 'frameworks/ATTCK/ICS.json'
        }
    },

    // JSON sanitization paths (glob patterns, relative to project root)
    sanitize: {
        paths: [
            'resources/**/*.json',
            'frameworks/ATTCK/**/*.json'
        ]
    },
    
    // Phase colors (IN/THROUGH/OUT) - distinct from framework colors
    phases: {
        in: '#10b981',       // Emerald green - entry/initial foothold
        through: '#06b6d4',  // Cyan - movement/propagation
        out: '#ef4444'       // Red - impact/action on objectives
    },
    
    // Framework colors (ATT&CK/CAPEC/CWE/Custom)
    frameworks: {
        attack: '#3b82f6',   // Blue
        capec: '#8b5cf6',    // Purple
        cwe: '#f59e0b',      // Orange
        custom: '#14b8a6'    // Teal
    },

    // STIX 2.1 SDO types available for custom items
    stixTypes: [
        { value: 'attack-pattern',   label: 'Attack Pattern' },
        { value: 'campaign',         label: 'Campaign' },
        { value: 'course-of-action', label: 'Course of Action' },
        { value: 'grouping',         label: 'Grouping' },
        { value: 'identity',         label: 'Identity' },
        { value: 'indicator',        label: 'Indicator' },
        { value: 'infrastructure',   label: 'Infrastructure' },
        { value: 'intrusion-set',    label: 'Intrusion Set' },
        { value: 'location',         label: 'Location' },
        { value: 'malware',          label: 'Malware' },
        { value: 'malware-analysis', label: 'Malware Analysis' },
        { value: 'note',             label: 'Note' },
        { value: 'observed-data',    label: 'Observed Data' },
        { value: 'opinion',          label: 'Opinion' },
        { value: 'report',           label: 'Report' },
        { value: 'threat-actor',     label: 'Threat Actor' },
        { value: 'tool',             label: 'Tool' },
        { value: 'vulnerability',    label: 'Vulnerability' },
        { value: 'x-custom',         label: 'Custom' }
    ],
    
    // UI colors (fallbacks, match default light theme)
    ui: {
        bgDark: '#f8fafc',
        bgCard: '#ffffff',
        bgPhase: '#f1f5f9',
        textPrimary: '#0f172a',
        textSecondary: '#475569',
        borderColor: '#e2e8f0',
        accent: '#94a3b8'
    },

    // Metadata icon colors (fallbacks)
    metaIcons: {
        defaultBg: 'rgba(255, 255, 255, 0.15)',
        defaultFg: '#0f172a',
        cveBg: 'rgba(239, 68, 68, 0.3)',
        cveFg: '#fca5a5',
        observableBg: 'rgba(59, 130, 246, 0.3)',
        observableFg: '#93c5fd',
        linkBg: 'rgba(139, 92, 246, 0.3)',
        linkFg: '#c4b5fd',
        commentBg: 'rgba(34, 197, 94, 0.3)',
        commentFg: '#86efac',
        confidenceBg: 'rgba(251, 191, 36, 0.3)',
        confidenceFg: '#fcd34d',
        brightness: 0.75
    },

    // Theme presets (light/dark) with optional schemes
    themes: {
        dark: {
            default: {
                ui: {
                    bgDark: '#1a1a1a',
                    bgCard: '#242424',
                    bgPhase: '#2d2d2d',
                    textPrimary: '#e5e5e5',
                    textSecondary: '#a3a3a3',
                    borderColor: '#404040',
                    accent: '#71717a'
                },
                metaIcons: {
                    defaultBg: 'rgba(255, 255, 255, 0.15)',
                    defaultFg: '#e5e5e5',
                    cveBg: 'rgba(239, 68, 68, 0.3)',
                    cveFg: '#fca5a5',
                    observableBg: 'rgba(59, 130, 246, 0.3)',
                    observableFg: '#93c5fd',
                    linkBg: 'rgba(139, 92, 246, 0.3)',
                    linkFg: '#c4b5fd',
                    commentBg: 'rgba(34, 197, 94, 0.3)',
                    commentFg: '#86efac',
                    confidenceBg: 'rgba(251, 191, 36, 0.3)',
                    confidenceFg: '#fcd34d',
                    brightness: 1
                }
            }
        },
        light: {
            default: {
                ui: {
                    bgDark: '#f8fafc',
                    bgCard: '#ffffff',
                    bgPhase: '#f1f5f9',
                    textPrimary: '#0f172a',
                    textSecondary: '#475569',
                    borderColor: '#e2e8f0',
                    accent: '#94a3b8'
                },
                metaIcons: {
                    defaultBg: 'rgba(15, 23, 42, 0.08)',
                    defaultFg: '#0f172a',
                    cveBg: 'rgba(239, 68, 68, 0.3)',
                    cveFg: '#fca5a5',
                    observableBg: 'rgba(59, 130, 246, 0.3)',
                    observableFg: '#93c5fd',
                    linkBg: 'rgba(139, 92, 246, 0.3)',
                    linkFg: '#c4b5fd',
                    commentBg: 'rgba(34, 197, 94, 0.3)',
                    commentFg: '#86efac',
                    confidenceBg: 'rgba(251, 191, 36, 0.3)',
                    confidenceFg: '#fcd34d',
                    brightness: 0.75
                }
            }
        }
    },

    // Theme defaults
    themeDefaults: {
        mode: 'light',
        scheme: 'default'
    },

    // Initial theme mode: 'light', 'dark', or 'auto' (OS preference)
    themeMode: 'auto',

    // Future config placeholders
    display: {
        maxNameLength: 200,      // Max width for entity names in tags
        maxDescLength: 800,      // Max description length in detail panel
        maxMitigations: 8,       // Max mitigations to show
        maxReferences: 3,        // Max references to show
        maxTitleLength: 200,     // Max kill chain title length
        maxCustomLabels: 20,     // Max labels per custom STIX item
        maxLabelLength: 50,      // Max chars per label
        maxCustomDescLength: 2000, // Max description length for custom items
        maxKillChainDescLength: 2000 // Max kill chain description length
    },

    // Navigation behavior
    navigation: {
        confirmOnLeave: true     // Show confirmation dialog before leaving the page
    }
};

// Resolve a theme from mode/scheme and merge with defaults
function resolveTheme(mode = CONFIG.themeDefaults?.mode, scheme = CONFIG.themeDefaults?.scheme) {
    const modeThemes = CONFIG.themes?.[mode] || CONFIG.themes?.dark || {};
    const schemeTheme = modeThemes[scheme] || modeThemes.default || {};

    return {
        phases: { ...CONFIG.phases, ...(schemeTheme.phases || {}) },
        frameworks: { ...CONFIG.frameworks, ...(schemeTheme.frameworks || {}) },
        ui: { ...CONFIG.ui, ...(schemeTheme.ui || {}) },
        metaIcons: { ...CONFIG.metaIcons, ...(schemeTheme.metaIcons || {}) }
    };
}

// Apply config colors to CSS variables
function applyConfigColors(theme) {
    const resolved = theme || resolveTheme();
    const root = document.documentElement;
    
    // Phase colors
    root.style.setProperty('--phase-in', resolved.phases.in);
    root.style.setProperty('--phase-through', resolved.phases.through);
    root.style.setProperty('--phase-out', resolved.phases.out);
    
    // Framework colors
    root.style.setProperty('--attack-color', resolved.frameworks.attack);
    root.style.setProperty('--capec-color', resolved.frameworks.capec);
    root.style.setProperty('--cwe-color', resolved.frameworks.cwe);
    root.style.setProperty('--custom-color', resolved.frameworks.custom);
    
    // UI colors
    root.style.setProperty('--bg-dark', resolved.ui.bgDark);
    root.style.setProperty('--bg-card', resolved.ui.bgCard);
    root.style.setProperty('--bg-phase', resolved.ui.bgPhase);
    root.style.setProperty('--bg-panel', resolved.ui.bgPhase);
    root.style.setProperty('--text-primary', resolved.ui.textPrimary);
    root.style.setProperty('--text-secondary', resolved.ui.textSecondary);
    root.style.setProperty('--border-color', resolved.ui.borderColor);
    root.style.setProperty('--accent', resolved.ui.accent);

    // Metadata icon colors
    root.style.setProperty('--meta-default-bg', resolved.metaIcons.defaultBg);
    root.style.setProperty('--meta-default-fg', resolved.metaIcons.defaultFg);
    root.style.setProperty('--meta-cve-bg', resolved.metaIcons.cveBg);
    root.style.setProperty('--meta-cve-fg', resolved.metaIcons.cveFg);
    root.style.setProperty('--meta-observable-bg', resolved.metaIcons.observableBg);
    root.style.setProperty('--meta-observable-fg', resolved.metaIcons.observableFg);
    root.style.setProperty('--meta-link-bg', resolved.metaIcons.linkBg);
    root.style.setProperty('--meta-link-fg', resolved.metaIcons.linkFg);
    root.style.setProperty('--meta-comment-bg', resolved.metaIcons.commentBg);
    root.style.setProperty('--meta-comment-fg', resolved.metaIcons.commentFg);
    root.style.setProperty('--meta-confidence-bg', resolved.metaIcons.confidenceBg);
    root.style.setProperty('--meta-confidence-fg', resolved.metaIcons.confidenceFg);
    root.style.setProperty('--meta-icon-brightness', resolved.metaIcons.brightness);
}

// Export for module usage (if needed)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { CONFIG, resolveTheme, applyConfigColors };
}

/**
 * Unified Kill Chain Visualizer
 * Maps MITRE ATT&CK techniques to the Unified Kill Chain framework
 * Supports all ATT&CK domains: Enterprise, Mobile, and ICS
 * 
 * @author Kill Chain Visualizer
 * @version 2.0.0
 */

class KillChainVisualizer {
    /**
     * MITRE ATT&CK Domains
     */
    static DOMAINS = {
        ENTERPRISE: 'enterprise',
        MOBILE: 'mobile',
        ICS: 'ics'
    };

    /**
     * Default color configuration - muted/monochrome theme
     */
    static defaultColors = {
        phaseIn: '#6b7280',      // Muted gray-blue
        phaseThrough: '#78716c', // Muted warm gray
        phaseOut: '#64748b',     // Slate gray
        bgDark: '#1a1a1a',
        bgCard: '#242424',
        bgPhase: '#2d2d2d',
        textPrimary: '#e5e5e5',
        textSecondary: '#a3a3a3',
        borderColor: '#404040',
        accent: '#71717a'        // Zinc accent
    };

    /**
     * @param {string} containerId - ID of the container element
     * @param {string} statsId - ID of the stats container element
     * @param {Object} options - Configuration options
     * @param {Object} options.colors - Custom color configuration
     */
    constructor(containerId, statsId, options = {}) {
        this.container = document.getElementById(containerId);
        this.statsContainer = document.getElementById(statsId);
        this.techniques = {};
        this.compactMode = false;
        this.showOnlyActivePhases = false;
        
        // Merge custom colors with defaults
        this.colors = { ...KillChainVisualizer.defaultColors, ...(options.colors || {}) };
        
        // Apply colors as CSS variables
        this.applyColors();
        
        // Define the Unified Kill Chain structure
        // Three super-phases: IN, THROUGH, OUT
        // Each contains multiple phases mapped to MITRE ATT&CK tactics
        this.killChainStructure = {
            'IN': {
                name: 'Initial Foothold',
                description: 'Getting into the network',
                phases: [
                    {
                        id: 'reconnaissance',
                        name: 'Reconnaissance',
                        description: 'Gathering information about the target',
                        tactics: ['reconnaissance'],
                        techniquePatterns: [
                            // Enterprise
                            'T1595', 'T1592', 'T1589', 'T1590', 'T1591', 'T1598', 'T1597', 'T1596', 'T1593', 'T1594'
                        ]
                    },
                    {
                        id: 'resource-development',
                        name: 'Resource Development',
                        description: 'Establishing resources to support operations',
                        tactics: ['resource-development'],
                        techniquePatterns: ['T1583', 'T1586', 'T1584', 'T1587', 'T1585', 'T1588', 'T1608']
                    },
                    {
                        id: 'delivery',
                        name: 'Delivery',
                        description: 'Delivering the payload to the target',
                        tactics: ['initial-access'],
                        techniquePatterns: [
                            // Enterprise
                            'T1566', 'T1189', 'T1195', 'T1091',
                            // Mobile
                            'T1474', 'T1475', 'T1476', 'T1477', 'T1478',
                            // ICS
                            'T0817', 'T0819', 'T0822', 'T0847', 'T0848', 'T0860', 'T0864', 'T0865', 'T0862', 'T0866'
                        ]
                    },
                    {
                        id: 'social-engineering',
                        name: 'Social Engineering',
                        description: 'Manipulating users to gain access',
                        tactics: ['initial-access'],
                        techniquePatterns: [
                            // Enterprise
                            'T1566', 'T1598', 'T1204',
                            // Mobile
                            'T1660', 'T1661', 'T1662', 'T1664', 'T1665'
                        ]
                    },
                    {
                        id: 'exploitation',
                        name: 'Exploitation',
                        description: 'Exploiting vulnerabilities for initial access',
                        tactics: ['initial-access', 'execution'],
                        techniquePatterns: [
                            // Enterprise
                            'T1190', 'T1203', 'T1189',
                            // Mobile
                            'T1456', 'T1458', 'T1664',
                            // ICS
                            'T0866', 'T0820', 'T0890'
                        ]
                    },
                    {
                        id: 'persistence',
                        name: 'Persistence',
                        description: 'Maintaining access to the compromised system',
                        tactics: ['persistence'],
                        techniquePatterns: [
                            // Enterprise
                            'T1098', 'T1197', 'T1547', 'T1037', 'T1176', 'T1554', 'T1136', 'T1543', 'T1546', 'T1574', 'T1525', 'T1556', 'T1137', 'T1542', 'T1053', 'T1505', 'T1205',
                            // Mobile
                            'T1398', 'T1400', 'T1402', 'T1540', 'T1541', 'T1577', 'T1624', 'T1625', 'T1626', 'T1645',
                            // ICS
                            'T0839', 'T0873', 'T0857', 'T0859'
                        ]
                    },
                    {
                        id: 'defense-evasion',
                        name: 'Defense Evasion',
                        description: 'Avoiding detection',
                        tactics: ['defense-evasion'],
                        techniquePatterns: [
                            // Enterprise
                            'T1548', 'T1134', 'T1197', 'T1140', 'T1610', 'T1006', 'T1484', 'T1480', 'T1211', 'T1222', 'T1564', 'T1574', 'T1562', 'T1070', 'T1202', 'T1036', 'T1556', 'T1578', 'T1112', 'T1601', 'T1599', 'T1027', 'T1542', 'T1055', 'T1207', 'T1014', 'T1218', 'T1216', 'T1221', 'T1205', 'T1127', 'T1535', 'T1550', 'T1078', 'T1497', 'T1600', 'T1220',
                            // Mobile
                            'T1407', 'T1406', 'T1418', 'T1420', 'T1422', 'T1444', 'T1447', 'T1508', 'T1516', 'T1523', 'T1575', 'T1576', 'T1617', 'T1628', 'T1629', 'T1630', 'T1631', 'T1632', 'T1633', 'T1634', 'T1644', 'T1646', 'T1648',
                            // ICS
                            'T0820', 'T0849', 'T0851', 'T0856', 'T0858', 'T0872'
                        ]
                    },
                    {
                        id: 'command-control',
                        name: 'Command & Control',
                        description: 'Establishing communication with compromised systems',
                        tactics: ['command-and-control'],
                        techniquePatterns: [
                            // Enterprise
                            'T1071', 'T1092', 'T1132', 'T1001', 'T1568', 'T1573', 'T1008', 'T1105', 'T1104', 'T1095', 'T1571', 'T1572', 'T1090', 'T1219', 'T1205', 'T1102',
                            // Mobile
                            'T1437', 'T1438', 'T1436', 'T1509', 'T1481', 'T1544', 'T1577', 'T1616', 'T1637', 'T1646',
                            // ICS
                            'T0869', 'T0884', 'T0885'
                        ]
                    }
                ]
            },
            'THROUGH': {
                name: 'Network Propagation',
                description: 'Moving through the network',
                phases: [
                    {
                        id: 'pivoting',
                        name: 'Pivoting',
                        description: 'Using compromised systems to access other systems',
                        tactics: ['lateral-movement'],
                        techniquePatterns: [
                            // Enterprise
                            'T1021', 'T1563', 'T1090',
                            // ICS
                            'T0886', 'T0859'
                        ]
                    },
                    {
                        id: 'discovery',
                        name: 'Discovery',
                        description: 'Understanding the network environment',
                        tactics: ['discovery'],
                        techniquePatterns: [
                            // Enterprise
                            'T1087', 'T1010', 'T1217', 'T1580', 'T1538', 'T1526', 'T1613', 'T1482', 'T1083', 'T1615', 'T1046', 'T1135', 'T1040', 'T1201', 'T1120', 'T1069', 'T1057', 'T1012', 'T1018', 'T1518', 'T1082', 'T1614', 'T1016', 'T1049', 'T1033', 'T1007', 'T1124', 'T1497',
                            // Mobile
                            'T1418', 'T1420', 'T1421', 'T1422', 'T1423', 'T1424', 'T1426', 'T1430', 'T1507', 'T1523', 'T1617', 'T1652',
                            // ICS
                            'T0840', 'T0842', 'T0846', 'T0854', 'T0887', 'T0888'
                        ]
                    },
                    {
                        id: 'privilege-escalation',
                        name: 'Privilege Escalation',
                        description: 'Gaining higher privileges',
                        tactics: ['privilege-escalation'],
                        techniquePatterns: [
                            // Enterprise
                            'T1548', 'T1134', 'T1547', 'T1484', 'T1611', 'T1068', 'T1574', 'T1055',
                            // Mobile
                            'T1404', 'T1626', 'T1631'
                        ]
                    },
                    {
                        id: 'execution',
                        name: 'Execution',
                        description: 'Running malicious code',
                        tactics: ['execution'],
                        techniquePatterns: [
                            // Enterprise
                            'T1059', 'T1609', 'T1610', 'T1203', 'T1559', 'T1106', 'T1053', 'T1129', 'T1072', 'T1569', 'T1204', 'T1047',
                            // Mobile
                            'T1575', 'T1623', 'T1624', 'T1658',
                            // ICS
                            'T0807', 'T0823', 'T0834', 'T0853', 'T0858', 'T0863', 'T0871'
                        ]
                    },
                    {
                        id: 'credential-access',
                        name: 'Credential Access',
                        description: 'Stealing credentials',
                        tactics: ['credential-access'],
                        techniquePatterns: [
                            // Enterprise
                            'T1557', 'T1110', 'T1555', 'T1212', 'T1187', 'T1606', 'T1056', 'T1556', 'T1111', 'T1621', 'T1040', 'T1003', 'T1528', 'T1558', 'T1539', 'T1552',
                            // Mobile
                            'T1409', 'T1411', 'T1414', 'T1417', 'T1439', 'T1517', 'T1634', 'T1635',
                            // ICS
                            'T0859', 'T0891'
                        ]
                    },
                    {
                        id: 'lateral-movement',
                        name: 'Lateral Movement',
                        description: 'Moving to other systems',
                        tactics: ['lateral-movement'],
                        techniquePatterns: [
                            // Enterprise
                            'T1210', 'T1534', 'T1570', 'T1563', 'T1021', 'T1091', 'T1072', 'T1080', 'T1550',
                            // Mobile
                            'T1427', 'T1428',
                            // ICS
                            'T0812', 'T0866', 'T0886', 'T0859', 'T0843'
                        ]
                    }
                ]
            },
            'OUT': {
                name: 'Action on Objectives',
                description: 'Achieving the attack goals',
                phases: [
                    {
                        id: 'collection',
                        name: 'Collection',
                        description: 'Gathering target data',
                        tactics: ['collection'],
                        techniquePatterns: [
                            // Enterprise
                            'T1560', 'T1123', 'T1119', 'T1185', 'T1115', 'T1530', 'T1602', 'T1213', 'T1005', 'T1039', 'T1025', 'T1074', 'T1114', 'T1056', 'T1113', 'T1125',
                            // Mobile
                            'T1429', 'T1430', 'T1432', 'T1433', 'T1435', 'T1507', 'T1512', 'T1513', 'T1517', 'T1533', 'T1636', 'T1638',
                            // ICS
                            'T0801', 'T0802', 'T0811', 'T0845', 'T0861', 'T0868', 'T0877', 'T0887'
                        ]
                    },
                    {
                        id: 'exfiltration',
                        name: 'Exfiltration',
                        description: 'Stealing data from the network',
                        tactics: ['exfiltration'],
                        techniquePatterns: [
                            // Enterprise
                            'T1020', 'T1030', 'T1048', 'T1041', 'T1011', 'T1052', 'T1567', 'T1029', 'T1537',
                            // Mobile
                            'T1438', 'T1437', 'T1639'
                        ]
                    },
                    {
                        id: 'impact',
                        name: 'Impact',
                        description: 'Disrupting, destroying, or manipulating systems',
                        tactics: ['impact'],
                        techniquePatterns: [
                            // Enterprise
                            'T1531', 'T1485', 'T1486', 'T1565', 'T1491', 'T1561', 'T1499', 'T1495', 'T1490', 'T1498', 'T1496', 'T1489', 'T1529',
                            // Mobile
                            'T1447', 'T1448', 'T1449', 'T1471', 'T1472', 'T1476', 'T1510', 'T1516', 'T1582', 'T1616', 'T1640', 'T1641', 'T1642', 'T1643',
                            // ICS
                            'T0800', 'T0806', 'T0813', 'T0814', 'T0815', 'T0816', 'T0826', 'T0827', 'T0828', 'T0829', 'T0830', 'T0831', 'T0832', 'T0835', 'T0836', 'T0837', 'T0838', 'T0879', 'T0880', 'T0881', 'T0882'
                        ]
                    },
                    {
                        id: 'objectives',
                        name: 'Objectives',
                        description: 'Final goals of the attack',
                        tactics: ['impact', 'exfiltration', 'collection'],
                        techniquePatterns: [] // Catch-all for objectives
                    }
                ]
            }
        };
        
        // Build technique to phase mapping
        this.buildTechniquePhaseMapping();
    }

    /**
     * Apply color configuration as CSS variables
     */
    applyColors() {
        const root = document.documentElement;
        root.style.setProperty('--phase-in', this.colors.phaseIn);
        root.style.setProperty('--phase-through', this.colors.phaseThrough);
        root.style.setProperty('--phase-out', this.colors.phaseOut);
        root.style.setProperty('--bg-dark', this.colors.bgDark);
        root.style.setProperty('--bg-card', this.colors.bgCard);
        root.style.setProperty('--bg-phase', this.colors.bgPhase);
        root.style.setProperty('--text-primary', this.colors.textPrimary);
        root.style.setProperty('--text-secondary', this.colors.textSecondary);
        root.style.setProperty('--border-color', this.colors.borderColor);
        root.style.setProperty('--accent', this.colors.accent);
    }

    /**
     * Update colors dynamically
     * @param {Object} newColors - New color configuration (partial or full)
     */
    setColors(newColors) {
        this.colors = { ...this.colors, ...newColors };
        this.applyColors();
        this.render();
        this.renderStats();
    }

    /**
     * Build a mapping from technique IDs to phases
     */
    buildTechniquePhaseMapping() {
        this.techniqueToPhase = {};
        
        for (const [superPhaseId, superPhase] of Object.entries(this.killChainStructure)) {
            for (const phase of superPhase.phases) {
                for (const pattern of phase.techniquePatterns) {
                    if (!this.techniqueToPhase[pattern]) {
                        this.techniqueToPhase[pattern] = [];
                    }
                    this.techniqueToPhase[pattern].push({
                        superPhase: superPhaseId,
                        phaseId: phase.id,
                        phaseName: phase.name
                    });
                }
            }
        }
    }

    /**
     * Parse MITRE ATT&CK Navigator layer JSON format
     * @param {Object} layerJson - Navigator layer JSON object
     * @param {Object} techniqueNames - Optional lookup table for technique names
     * @returns {Object} - Techniques object { id: name }
     */
    parseNavigatorLayer(layerJson, techniqueNames = {}) {
        const techniques = {};
        
        if (!layerJson || !layerJson.techniques) {
            console.warn('Invalid Navigator layer format');
            return techniques;
        }
        
        // Extract domain from layer
        const domain = layerJson.domain || 'enterprise-attack';
        
        // Process each technique entry
        for (const tech of layerJson.techniques) {
            // Only include enabled techniques
            if (tech.enabled === false) {
                continue;
            }
            
            const techId = tech.techniqueID;
            
            // Skip if already added (Navigator can have duplicates for multi-tactic techniques)
            if (techniques[techId]) {
                continue;
            }
            
            // Use provided name, lookup table, or generate placeholder
            const name = techniqueNames[techId] || 
                         this.getTechniqueName(techId) || 
                         `Technique ${techId}`;
            
            techniques[techId] = name;
        }
        
        return techniques;
    }

    /**
     * Common technique name lookup (subset of most common techniques)
     * @param {string} techId - Technique ID
     * @returns {string|null} - Technique name or null
     */
    getTechniqueName(techId) {
        // Common technique names lookup table
        const commonNames = {
            // Enterprise - Initial Access
            'T1189': 'Drive-by Compromise',
            'T1190': 'Exploit Public-Facing Application',
            'T1133': 'External Remote Services',
            'T1200': 'Hardware Additions',
            'T1566': 'Phishing',
            'T1566.001': 'Spearphishing Attachment',
            'T1566.002': 'Spearphishing Link',
            'T1566.003': 'Spearphishing via Service',
            'T1091': 'Replication Through Removable Media',
            'T1195': 'Supply Chain Compromise',
            'T1199': 'Trusted Relationship',
            'T1078': 'Valid Accounts',
            // Enterprise - Execution
            'T1059': 'Command and Scripting Interpreter',
            'T1059.001': 'PowerShell',
            'T1059.003': 'Windows Command Shell',
            'T1059.004': 'Unix Shell',
            'T1203': 'Exploitation for Client Execution',
            'T1204': 'User Execution',
            'T1047': 'Windows Management Instrumentation',
            // Enterprise - Persistence
            'T1098': 'Account Manipulation',
            'T1547': 'Boot or Logon Autostart Execution',
            'T1136': 'Create Account',
            'T1543': 'Create or Modify System Process',
            'T1053': 'Scheduled Task/Job',
            // Enterprise - Privilege Escalation
            'T1548': 'Abuse Elevation Control Mechanism',
            'T1134': 'Access Token Manipulation',
            'T1068': 'Exploitation for Privilege Escalation',
            'T1055': 'Process Injection',
            // Enterprise - Defense Evasion
            'T1070': 'Indicator Removal',
            'T1036': 'Masquerading',
            'T1027': 'Obfuscated Files or Information',
            'T1562': 'Impair Defenses',
            // Enterprise - Credential Access
            'T1110': 'Brute Force',
            'T1003': 'OS Credential Dumping',
            'T1003.001': 'LSASS Memory',
            'T1558': 'Steal or Forge Kerberos Tickets',
            // Enterprise - Discovery
            'T1087': 'Account Discovery',
            'T1082': 'System Information Discovery',
            'T1083': 'File and Directory Discovery',
            'T1046': 'Network Service Discovery',
            'T1135': 'Network Share Discovery',
            // Enterprise - Lateral Movement
            'T1021': 'Remote Services',
            'T1021.001': 'Remote Desktop Protocol',
            'T1021.002': 'SMB/Windows Admin Shares',
            'T1570': 'Lateral Tool Transfer',
            // Enterprise - Collection
            'T1560': 'Archive Collected Data',
            'T1005': 'Data from Local System',
            'T1114': 'Email Collection',
            'T1113': 'Screen Capture',
            // Enterprise - C2
            'T1071': 'Application Layer Protocol',
            'T1105': 'Ingress Tool Transfer',
            'T1572': 'Protocol Tunneling',
            'T1090': 'Proxy',
            // Enterprise - Exfiltration
            'T1041': 'Exfiltration Over C2 Channel',
            'T1567': 'Exfiltration Over Web Service',
            'T1048': 'Exfiltration Over Alternative Protocol',
            // Enterprise - Impact
            'T1486': 'Data Encrypted for Impact',
            'T1485': 'Data Destruction',
            'T1489': 'Service Stop',
            'T1490': 'Inhibit System Recovery',
            
            // ICS Techniques
            'T0800': 'Activate Firmware Update Mode',
            'T0801': 'Monitor Process State',
            'T0802': 'Automated Collection',
            'T0803': 'Block Command Message',
            'T0804': 'Block Reporting Message',
            'T0805': 'Block Serial COM',
            'T0806': 'Brute Force I/O',
            'T0807': 'Command-Line Interface',
            'T0809': 'Data Destruction',
            'T0811': 'Data from Information Repositories',
            'T0812': 'Default Credentials',
            'T0813': 'Denial of Control',
            'T0814': 'Denial of Service',
            'T0815': 'Denial of View',
            'T0816': 'Device Restart/Shutdown',
            'T0817': 'Drive-by Compromise',
            'T0819': 'Exploit Public-Facing Application',
            'T0820': 'Exploitation for Evasion',
            'T0821': 'Modify Controller Tasking',
            'T0822': 'External Remote Services',
            'T0823': 'Graphical User Interface',
            'T0826': 'Loss of Availability',
            'T0827': 'Loss of Control',
            'T0828': 'Loss of Productivity and Revenue',
            'T0829': 'Loss of Safety',
            'T0830': 'Man in the Middle',
            'T0831': 'Manipulation of Control',
            'T0832': 'Manipulation of View',
            'T0834': 'Native API',
            'T0835': 'Manipulate I/O Image',
            'T0836': 'Modify Parameter',
            'T0837': 'Loss of Protection',
            'T0838': 'Modify Alarm Settings',
            'T0839': 'Module Firmware',
            'T0840': 'Network Connection Enumeration',
            'T0842': 'Network Sniffing',
            'T0843': 'Program Download',
            'T0845': 'Program Upload',
            'T0846': 'Remote System Discovery',
            'T0847': 'Replication Through Removable Media',
            'T0848': 'Rogue Master',
            'T0849': 'Masquerading',
            'T0851': 'Rootkit',
            'T0852': 'Screen Capture',
            'T0853': 'Scripting',
            'T0855': 'Unauthorized Command Message',
            'T0856': 'Spoof Reporting Message',
            'T0857': 'System Firmware',
            'T0858': 'Change Operating Mode',
            'T0859': 'Valid Accounts',
            'T0860': 'Wireless Compromise',
            'T0861': 'Point & Tag Identification',
            'T0862': 'Supply Chain Compromise',
            'T0863': 'User Execution',
            'T0864': 'Transient Cyber Asset',
            'T0865': 'Spearphishing Attachment',
            'T0866': 'Exploitation of Remote Services',
            'T0867': 'Lateral Tool Transfer',
            'T0868': 'Detect Operating Mode',
            'T0869': 'Standard Application Layer Protocol',
            'T0871': 'Execution through API',
            'T0872': 'Indicator Removal on Host',
            'T0873': 'Project File Infection',
            'T0874': 'Hooking',
            'T0877': 'I/O Image',
            'T0878': 'Alarm Suppression',
            'T0879': 'Damage to Property',
            'T0880': 'Loss of Safety',
            'T0881': 'Service Stop',
            'T0882': 'Theft of Operational Information',
            'T0883': 'Internet Accessible Device',
            'T0884': 'Connection Proxy',
            'T0885': 'Commonly Used Port',
            'T0886': 'Remote Services',
            'T0887': 'Wireless Sniffing',
            'T0888': 'Remote System Information Discovery',
            'T0889': 'Modify Program',
            'T0890': 'Exploitation for Privilege Escalation',
            'T0891': 'Hardcoded Credentials',
            'T0892': 'Change Credential',
            'T0893': 'Data from Local System',
            'T0894': 'System Location Discovery',
            'T0895': 'Autorun Image',
            
            // Mobile Techniques
            'T1398': 'Boot or Logon Initialization Scripts',
            'T1399': 'Broadcast Receivers',
            'T1401': 'Device Administrator Permissions',
            'T1402': 'Broadcast Receivers',
            'T1404': 'Exploitation for Privilege Escalation',
            'T1406': 'Obfuscated Files or Information',
            'T1407': 'Download New Code at Runtime',
            'T1409': 'Stored Application Data',
            'T1410': 'Network Traffic Capture or Redirection',
            'T1411': 'Input Prompt',
            'T1414': 'Clipboard Data',
            'T1417': 'Input Capture',
            'T1418': 'Software Discovery',
            'T1420': 'File and Directory Discovery',
            'T1421': 'System Network Connections Discovery',
            'T1422': 'System Network Configuration Discovery',
            'T1423': 'Network Service Scanning',
            'T1424': 'Process Discovery',
            'T1426': 'System Information Discovery',
            'T1427': 'Attack PC via USB Connection',
            'T1428': 'Exploitation of Remote Services',
            'T1429': 'Audio Capture',
            'T1430': 'Location Tracking',
            'T1432': 'Access Contact List',
            'T1433': 'Access Call Log',
            'T1435': 'Access Calendar Entries',
            'T1437': 'Standard Application Layer Protocol',
            'T1438': 'Alternate Network Mediums',
            'T1444': 'Masquerade as Legitimate Application',
            'T1447': 'Delete Device Data',
            'T1448': 'Carrier Billing Fraud',
            'T1449': 'Exploit SS7 to Redirect Phone Calls',
            'T1453': 'Abuse Accessibility Features',
            'T1456': 'Drive-by Compromise',
            'T1458': 'Replication Through Removable Media',
            'T1461': 'Lockscreen Bypass',
            'T1471': 'Data Encrypted for Impact',
            'T1472': 'Generate Fraudulent Advertising Revenue',
            'T1474': 'Supply Chain Compromise',
            'T1476': 'Deliver Malicious App via Authorized App Store',
            'T1477': 'Exploit via Radio Interfaces',
            'T1478': 'Install Insecure or Malicious Configuration',
            'T1481': 'Web Service',
            'T1507': 'Network Information Discovery',
            'T1508': 'Suppress Application Icon',
            'T1509': 'Non-Standard Port',
            'T1510': 'Clipboard Modification',
            'T1512': 'Video Capture',
            'T1513': 'Screen Capture',
            'T1516': 'Input Injection',
            'T1517': 'Access Notifications',
            'T1523': 'Evade Analysis Environment',
            'T1533': 'Data from Local System',
            'T1540': 'Code Injection',
            'T1541': 'Foreground Persistence',
            'T1544': 'Ingress Tool Transfer',
            'T1575': 'Native Code',
            'T1577': 'Compromise Application Executable',
            'T1582': 'SMS Control',
            'T1603': 'Scheduled Task/Job',
            'T1604': 'Proxy Through Victim',
            'T1616': 'Call Control',
            'T1617': 'Hooking',
            'T1623': 'Command and Scripting Interpreter',
            'T1624': 'Event Triggered Execution',
            'T1625': 'Hijack Execution Flow',
            'T1626': 'Abuse Elevation Control Mechanism',
            'T1627': 'Execution Guardrails',
            'T1628': 'Hide Artifacts',
            'T1629': 'Impair Defenses',
            'T1630': 'Indicator Removal on Host',
            'T1631': 'Process Injection',
            'T1632': 'Subvert Trust Controls',
            'T1633': 'Virtualization/Sandbox Evasion',
            'T1634': 'Credentials from Password Store',
            'T1635': 'Steal Application Access Token',
            'T1636': 'Protected User Data',
            'T1637': 'Dynamic Resolution',
            'T1638': 'Adversary-in-the-Middle',
            'T1639': 'Exfiltration Over Alternative Protocol',
            'T1640': 'Account Access Removal',
            'T1641': 'Data Manipulation',
            'T1642': 'Endpoint Denial of Service',
            'T1643': 'Generate Fraudulent Advertising Revenue',
            'T1644': 'Out of Band Data',
            'T1645': 'Modify System Image',
            'T1646': 'Exfiltration Over C2 Channel',
            'T1648': 'Serverless Execution',
            'T1652': 'Device Driver Discovery',
            'T1658': 'Exploitation for Client Execution',
            'T1660': 'Phishing',
            'T1661': 'Application Versioning',
            'T1662': 'Network Denial of Service',
            'T1663': 'Remote Access Software',
            'T1664': 'Exploitation for Initial Access',
            'T1665': 'Obtain Device Cloud Backups'
        };
        
        return commonNames[techId] || null;
    }

    /**
     * Set techniques to visualize
     * @param {Object} techniques - Associative array of technique_id => technique_name
     */
    setTechniques(techniques) {
        this.techniques = techniques;
        this.mappedTechniques = this.mapTechniquesToPhases(techniques);
        this.render();
        this.renderStats();
    }

    /**
     * Map techniques to kill chain phases
     * @param {Object} techniques - Associative array of technique_id => technique_name
     * @returns {Object} - Mapped techniques by super-phase and phase
     */
    mapTechniquesToPhases(techniques) {
        const mapped = {
            'IN': {},
            'THROUGH': {},
            'OUT': {}
        };

        // Initialize all phases
        for (const [superPhaseId, superPhase] of Object.entries(this.killChainStructure)) {
            for (const phase of superPhase.phases) {
                mapped[superPhaseId][phase.id] = [];
            }
        }

        // Map each technique to its phase(s)
        for (const [techId, techName] of Object.entries(techniques)) {
            const baseId = techId.split('.')[0]; // Get base technique ID
            let assigned = false;

            // Try exact match first, then base ID
            for (const searchId of [techId, baseId]) {
                if (this.techniqueToPhase[searchId]) {
                    for (const mapping of this.techniqueToPhase[searchId]) {
                        mapped[mapping.superPhase][mapping.phaseId].push({
                            id: techId,
                            name: techName
                        });
                        assigned = true;
                    }
                    break;
                }
            }

            // If not assigned, try pattern matching
            if (!assigned) {
                for (const [superPhaseId, superPhase] of Object.entries(this.killChainStructure)) {
                    for (const phase of superPhase.phases) {
                        for (const pattern of phase.techniquePatterns) {
                            if (techId.startsWith(pattern) || baseId === pattern) {
                                mapped[superPhaseId][phase.id].push({
                                    id: techId,
                                    name: techName
                                });
                                assigned = true;
                                break;
                            }
                        }
                        if (assigned) break;
                    }
                    if (assigned) break;
                }
            }

            // If still not assigned, put in a default phase based on technique ID ranges
            if (!assigned) {
                const defaultPhase = this.guessPhaseFromId(techId);
                if (defaultPhase) {
                    mapped[defaultPhase.superPhase][defaultPhase.phaseId].push({
                        id: techId,
                        name: techName
                    });
                }
            }
        }

        return mapped;
    }

    /**
     * Detect the ATT&CK domain from a technique ID
     * @param {string} techId - Technique ID (e.g., T1566, T0800)
     * @returns {string} - Domain identifier
     */
    detectDomain(techId) {
        const baseId = techId.replace('T', '').split('.')[0];
        const numId = parseInt(baseId);
        
        // ICS techniques use T0xxx format (three digits starting with 0)
        if (baseId.startsWith('0') || (numId >= 800 && numId <= 899)) {
            return KillChainVisualizer.DOMAINS.ICS;
        }
        
        // Mobile-specific technique ranges (T1xxx but mobile-only)
        // Mobile techniques: T1398-T1448, T1471-T1478, T1507-T1533, T1575-T1665
        if ((numId >= 1398 && numId <= 1448) ||
            (numId >= 1471 && numId <= 1478) ||
            (numId >= 1507 && numId <= 1533) ||
            (numId >= 1575 && numId <= 1665 && !this.isEnterpriseTechnique(numId))) {
            return KillChainVisualizer.DOMAINS.MOBILE;
        }
        
        return KillChainVisualizer.DOMAINS.ENTERPRISE;
    }

    /**
     * Check if a technique ID is in the Enterprise domain
     * (Some T1xxx IDs overlap, this helps disambiguate)
     */
    isEnterpriseTechnique(numId) {
        // Known Enterprise technique ranges that might overlap with Mobile
        const enterpriseRanges = [
            [1001, 1220], [1480, 1500], [1530, 1570], [1595, 1620]
        ];
        return enterpriseRanges.some(([min, max]) => numId >= min && numId <= max);
    }

    /**
     * Guess phase from technique ID based on MITRE ATT&CK numbering
     */
    guessPhaseFromId(techId) {
        const domain = this.detectDomain(techId);
        const baseId = parseInt(techId.replace('T', '').split('.')[0]);
        
        // ICS domain mappings
        if (domain === KillChainVisualizer.DOMAINS.ICS) {
            if (baseId >= 817 && baseId <= 866) return { superPhase: 'IN', phaseId: 'delivery' };
            if (baseId >= 839 && baseId <= 873) return { superPhase: 'IN', phaseId: 'persistence' };
            if (baseId >= 840 && baseId <= 888) return { superPhase: 'THROUGH', phaseId: 'discovery' };
            if (baseId >= 807 && baseId <= 871) return { superPhase: 'THROUGH', phaseId: 'execution' };
            if (baseId >= 812 && baseId <= 886) return { superPhase: 'THROUGH', phaseId: 'lateral-movement' };
            if (baseId >= 801 && baseId <= 877) return { superPhase: 'OUT', phaseId: 'collection' };
            if (baseId >= 800 && baseId <= 882) return { superPhase: 'OUT', phaseId: 'impact' };
            return { superPhase: 'OUT', phaseId: 'objectives' };
        }
        
        // Mobile domain mappings
        if (domain === KillChainVisualizer.DOMAINS.MOBILE) {
            if (baseId >= 1474 && baseId <= 1478) return { superPhase: 'IN', phaseId: 'delivery' };
            if (baseId >= 1660 && baseId <= 1665) return { superPhase: 'IN', phaseId: 'social-engineering' };
            if (baseId >= 1398 && baseId <= 1402) return { superPhase: 'IN', phaseId: 'persistence' };
            if (baseId >= 1540 && baseId <= 1541) return { superPhase: 'IN', phaseId: 'persistence' };
            if (baseId >= 1418 && baseId <= 1430) return { superPhase: 'THROUGH', phaseId: 'discovery' };
            if (baseId >= 1404 && baseId <= 1417) return { superPhase: 'THROUGH', phaseId: 'credential-access' };
            if (baseId >= 1429 && baseId <= 1435) return { superPhase: 'OUT', phaseId: 'collection' };
            if (baseId >= 1636 && baseId <= 1639) return { superPhase: 'OUT', phaseId: 'exfiltration' };
            if (baseId >= 1447 && baseId <= 1472) return { superPhase: 'OUT', phaseId: 'impact' };
            return { superPhase: 'OUT', phaseId: 'objectives' };
        }
        
        // Enterprise domain mappings (original logic)
        if (baseId >= 1595 && baseId <= 1598) return { superPhase: 'IN', phaseId: 'reconnaissance' };
        if (baseId >= 1583 && baseId <= 1608) return { superPhase: 'IN', phaseId: 'resource-development' };
        if (baseId >= 1189 && baseId <= 1199) return { superPhase: 'IN', phaseId: 'exploitation' };
        if (baseId >= 1059 && baseId <= 1072) return { superPhase: 'THROUGH', phaseId: 'execution' };
        if (baseId >= 1087 && baseId <= 1135) return { superPhase: 'THROUGH', phaseId: 'discovery' };
        if (baseId >= 1003 && baseId <= 1056) return { superPhase: 'THROUGH', phaseId: 'credential-access' };
        if (baseId >= 1560 && baseId <= 1602) return { superPhase: 'OUT', phaseId: 'collection' };
        if (baseId >= 1020 && baseId <= 1052) return { superPhase: 'OUT', phaseId: 'exfiltration' };
        if (baseId >= 1485 && baseId <= 1531) return { superPhase: 'OUT', phaseId: 'impact' };
        
        return { superPhase: 'OUT', phaseId: 'objectives' };
    }

    /**
     * Render the kill chain visualization
     */
    render() {
        this.container.textContent = '';

        const superPhases = ['IN', 'THROUGH', 'OUT'];
        
        superPhases.forEach((superPhaseId, index) => {
            const superPhase = this.killChainStructure[superPhaseId];
            const superPhaseEl = this.createSuperPhase(superPhaseId, superPhase);
            this.container.appendChild(superPhaseEl);

            // Add flow arrow between super-phases
            if (index < superPhases.length - 1) {
                const arrow = document.createElement('div');
                arrow.className = 'flow-arrow';
                arrow.textContent = '→';
                this.container.appendChild(arrow);
            }
        });
    }

    /**
     * Create a super-phase element (IN, THROUGH, OUT)
     */
    createSuperPhase(id, superPhase) {
        const el = document.createElement('div');
        el.className = `super-phase ${id.toLowerCase()}`;
        el.dataset.superPhase = id;

        const header = document.createElement('div');
        header.className = 'super-phase-header';
        const headerTitle = document.createElement('span');
        headerTitle.textContent = id;
        const headerSub = document.createElement('small');
        headerSub.style.display = 'block';
        headerSub.style.fontSize = '0.7em';
        headerSub.style.opacity = '0.8';
        headerSub.textContent = superPhase.name || '';
        header.appendChild(headerTitle);
        header.appendChild(headerSub);
        el.appendChild(header);

        const content = document.createElement('div');
        content.className = 'super-phase-content';

        for (const phase of superPhase.phases) {
            const techniques = this.mappedTechniques[id][phase.id] || [];
            
            if (this.showOnlyActivePhases && techniques.length === 0) {
                continue;
            }

            const phaseEl = this.createPhase(phase, techniques);
            content.appendChild(phaseEl);
        }

        el.appendChild(content);
        return el;
    }

    /**
     * Create a phase element with techniques
     */
    createPhase(phase, techniques) {
        const el = document.createElement('div');
        el.className = `phase ${techniques.length === 0 ? 'empty' : ''}`;
        el.dataset.phaseId = phase.id;

        const header = document.createElement('div');
        header.className = 'phase-header';
        const title = document.createElement('div');
        title.className = 'phase-title';

        const name = document.createElement('span');
        name.className = 'phase-name';
        name.textContent = phase.name || '';

        const count = document.createElement('span');
        count.className = `phase-count ${techniques.length === 0 ? 'zero' : ''}`;
        count.textContent = String(techniques.length);

        title.appendChild(name);
        title.appendChild(count);

        const toggle = document.createElement('span');
        toggle.className = 'phase-toggle';
        toggle.textContent = '▼';

        header.appendChild(title);
        header.appendChild(toggle);
        header.addEventListener('click', () => this.togglePhase(el));
        el.appendChild(header);

        const content = document.createElement('div');
        content.className = `phase-content ${this.compactMode ? 'compact' : ''}`;
        content.title = phase.description;

        // Sort techniques by ID
        techniques.sort((a, b) => a.id.localeCompare(b.id));

        for (const technique of techniques) {
            const techEl = this.createTechnique(technique);
            content.appendChild(techEl);
        }

        if (techniques.length === 0) {
            const emptyMsg = document.createElement('div');
            emptyMsg.className = 'empty-state';
            const small = document.createElement('small');
            small.textContent = 'No techniques in this phase';
            emptyMsg.appendChild(small);
            content.appendChild(emptyMsg);
        }

        el.appendChild(content);
        return el;
    }

    /**
     * Create a technique tag element
     */
    createTechnique(technique) {
        const domain = this.detectDomain(technique.id);
        const domainLabel = domain !== KillChainVisualizer.DOMAINS.ENTERPRISE ? ` [${domain.toUpperCase()}]` : '';
        
        const el = document.createElement('div');
        el.className = `technique domain-${domain}`;
        el.title = `${technique.id}: ${technique.name}${domainLabel}`;

        const idEl = document.createElement('span');
        idEl.className = 'technique-id';
        idEl.textContent = technique.id;

        const nameEl = document.createElement('span');
        nameEl.className = 'technique-name';
        nameEl.textContent = technique.name;

        el.appendChild(idEl);
        el.appendChild(nameEl);
        
        // Add click handler for MITRE ATT&CK link
        // KCE-SEC-002: Use noopener to prevent tabnabbing
        el.addEventListener('click', () => {
            const url = this.getMitreAttackUrl(technique.id);
            window.open(url, '_blank', 'noopener,noreferrer');
        });
        el.style.cursor = 'pointer';
        
        return el;
    }

    /**
     * Generate the correct MITRE ATT&CK URL for a technique
     * @param {string} techId - Technique ID
     * @returns {string} - Full URL to MITRE ATT&CK page
     */
    getMitreAttackUrl(techId) {
        const domain = this.detectDomain(techId);
        const baseId = techId.split('.')[0];
        const subId = techId.includes('.') ? techId.split('.')[1] : null;
        
        // Domain-specific URL paths
        const domainPaths = {
            [KillChainVisualizer.DOMAINS.ENTERPRISE]: 'techniques',
            [KillChainVisualizer.DOMAINS.MOBILE]: 'techniques/mobile',
            [KillChainVisualizer.DOMAINS.ICS]: 'techniques/ics'
        };
        
        let url = `https://attack.mitre.org/${domainPaths[domain]}/${baseId}/`;
        if (subId) {
            url += `${subId.padStart(3, '0')}/`;
        }
        return url;
    }

    /**
     * Toggle phase expansion/collapse
     */
    togglePhase(phaseEl) {
        phaseEl.classList.toggle('minimized');
    }

    /**
     * Expand all phases
     */
    expandAll() {
        document.querySelectorAll('.phase').forEach(phase => {
            phase.classList.remove('minimized');
        });
    }

    /**
     * Collapse all phases
     */
    collapseAll() {
        document.querySelectorAll('.phase').forEach(phase => {
            phase.classList.add('minimized');
        });
    }

    /**
     * Toggle compact mode for techniques
     */
    toggleCompactMode() {
        this.compactMode = !this.compactMode;
        document.querySelectorAll('.phase-content').forEach(content => {
            content.classList.toggle('compact', this.compactMode);
        });
    }

    /**
     * Show only phases with techniques
     */
    showOnlyActive() {
        this.showOnlyActivePhases = !this.showOnlyActivePhases;
        this.render();
    }

    /**
     * Reset the view
     */
    resetView() {
        this.compactMode = false;
        this.showOnlyActivePhases = false;
        this.render();
        this.expandAll();
    }

    /**
     * Render statistics
     */
    renderStats() {
        const totalTechniques = Object.keys(this.techniques).length;
        let inCount = 0, throughCount = 0, outCount = 0;
        let phaseCount = 0;

        for (const [superPhaseId, phases] of Object.entries(this.mappedTechniques)) {
            for (const [phaseId, techniques] of Object.entries(phases)) {
                if (techniques.length > 0) phaseCount++;
                
                switch(superPhaseId) {
                    case 'IN': inCount += techniques.length; break;
                    case 'THROUGH': throughCount += techniques.length; break;
                    case 'OUT': outCount += techniques.length; break;
                }
            }
        }

        this.statsContainer.innerHTML = `
            <div class="stat">
                <div class="stat-value">${totalTechniques}</div>
                <div class="stat-label">Total Techniques</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color: var(--phase-in)">${inCount}</div>
                <div class="stat-label">IN Phase</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color: var(--phase-through)">${throughCount}</div>
                <div class="stat-label">THROUGH Phase</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color: var(--phase-out)">${outCount}</div>
                <div class="stat-label">OUT Phase</div>
            </div>
            <div class="stat">
                <div class="stat-value">${phaseCount}</div>
                <div class="stat-label">Active Phases</div>
            </div>
        `;
    }

    /**
     * Get techniques for a specific phase
     */
    getTechniquesForPhase(superPhase, phaseId) {
        return this.mappedTechniques[superPhase]?.[phaseId] || [];
    }

    /**
     * Export the current visualization data
     */
    exportData() {
        return {
            techniques: this.techniques,
            mappedTechniques: this.mappedTechniques,
            stats: {
                total: Object.keys(this.techniques).length,
                in: Object.values(this.mappedTechniques.IN).flat().length,
                through: Object.values(this.mappedTechniques.THROUGH).flat().length,
                out: Object.values(this.mappedTechniques.OUT).flat().length
            }
        };
    }

    /**
     * Highlight specific techniques
     */
    highlightTechniques(techniqueIds) {
        // Remove existing highlights
        document.querySelectorAll('.technique.highlighted').forEach(el => {
            el.classList.remove('highlighted');
        });

        // Add highlights
        techniqueIds.forEach(id => {
            document.querySelectorAll(`.technique`).forEach(el => {
                if (el.querySelector('.technique-id').textContent === id) {
                    el.classList.add('highlighted');
                    el.style.boxShadow = '0 0 10px var(--highlight)';
                }
            });
        });
    }

    /**
     * Clear all highlights
     */
    clearHighlights() {
        document.querySelectorAll('.technique').forEach(el => {
            el.classList.remove('highlighted');
            el.style.boxShadow = '';
        });
    }
}

// Make it available globally
if (typeof window !== 'undefined') {
    window.KillChainVisualizer = KillChainVisualizer;
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = KillChainVisualizer;
}

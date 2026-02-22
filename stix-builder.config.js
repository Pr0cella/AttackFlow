'use strict';

// STIX 2.1 Builder Config
const STIX_VERSION = '2.1';
const STIX_ID_PATTERN = /^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const STIX_KILL_CHAIN_PHASES = {
    'unified-kill-chain': [
        'reconnaissance',
        'resource-development',
        'delivery',
        'social-engineering',
        'exploitation',
        'persistence',
        'defense-evasion',
        'command-and-control',
        'pivoting',
        'discovery',
        'privilege-escalation',
        'execution',
        'credential-access',
        'lateral-movement',
        'collection',
        'exfiltration',
        'impact',
        'objectives'
    ]
};

const STIX_VOCABULARIES = {
    'attack-motivation-ov': [
        'accidental', 'coercion', 'dominance', 'ideology', 'notoriety',
        'organizational-gain', 'personal-gain', 'personal-satisfaction',
        'revenge', 'unpredictable'
    ],
    'attack-resource-level-ov': [
        'individual', 'club', 'contest', 'team', 'organization', 'government'
    ],
    'grouping-context-ov': [
        'suspicious-activity', 'malware-analysis', 'unspecified'
    ],
    'identity-class-ov': [
        'individual', 'group', 'system', 'organization', 'class', 'unknown'
    ],
    'implementation-language-ov': [
        'applescript', 'bash', 'c', 'c++', 'c#', 'go', 'java', 'javascript',
        'lua', 'objective-c', 'perl', 'php', 'powershell', 'python', 'ruby',
        'rust', 'scala', 'swift', 'typescript', 'visual-basic'
    ],
    'indicator-type-ov': [
        'anomalous-activity', 'anonymization', 'benign', 'compromised',
        'malicious-activity', 'attribution', 'unknown'
    ],
    'infrastructure-type-ov': [
        'amplification', 'anonymization', 'botnet', 'command-and-control',
        'control-system', 'exfiltration', 'firewall', 'hosting-malware',
        'hosting-target-lists', 'phishing', 'reconnaissance', 'routers-switches',
        'staging', 'workstation', 'unknown'
    ],
    'malware-type-ov': [
        'adware', 'backdoor', 'bot', 'bootkit', 'ddos', 'downloader',
        'dropper', 'exploit-kit', 'keylogger', 'ransomware', 'remote-access-trojan',
        'resource-exploitation', 'rogue-security-software', 'rootkit',
        'screen-capture', 'spyware', 'trojan', 'unknown', 'virus', 'webshell',
        'wiper', 'worm'
    ],
    'malware-capabilities-ov': [
        'accesses-remote-machines', 'anti-debugging', 'anti-disassembly',
        'anti-emulation', 'anti-memory-forensics', 'anti-sandbox',
        'anti-virus-evasion', 'captures-input-peripherals', 'captures-output-peripherals',
        'captures-system-state-data', 'cleans-traces-of-infection',
        'commits-fraud', 'communicates-with-c2', 'compromises-data-availability',
        'compromises-data-integrity', 'compromises-system-availability',
        'controls-local-machine', 'degrades-security-software',
        'degrades-system-updates', 'determines-c2-server', 'emails-spam',
        'escalates-privileges', 'evades-av', 'exfiltrates-data',
        'fingerprints-host', 'hides-artifacts', 'hides-executing-code',
        'infects-files', 'infects-remote-machines', 'installs-other-components',
        'persists-after-system-reboot', 'prevents-artifact-access',
        'prevents-artifact-deletion', 'probes-network-environment',
        'self-modifies', 'steals-authentication-credentials',
        'violates-system-operational-integrity'
    ],
    'malware-result-ov': [
        'malicious', 'suspicious', 'benign', 'unknown'
    ],
    'opinion-enum': [
        'strongly-disagree', 'disagree', 'neutral', 'agree', 'strongly-agree'
    ],
    'pattern-type-ov': [
        'stix', 'pcre', 'sigma', 'snort', 'suricata', 'yara'
    ],
    'processor-architecture-ov': [
        'alpha', 'arm', 'ia-64', 'mips', 'powerpc', 'sparc', 'x86', 'x86-64'
    ],
    'report-type-ov': [
        'attack-pattern', 'campaign', 'identity', 'indicator', 'intrusion-set',
        'malware', 'observed-data', 'threat-actor', 'threat-report', 'tool',
        'vulnerability'
    ],
    'threat-actor-type-ov': [
        'activist', 'competitor', 'crime-syndicate', 'criminal', 'hacker',
        'insider-accidental', 'insider-disgruntled', 'nation-state', 'sensationalist',
        'spy', 'terrorist', 'unknown'
    ],
    'threat-actor-role-ov': [
        'agent', 'director', 'independent', 'infrastructure-architect',
        'infrastructure-operator', 'malware-author', 'sponsor'
    ],
    'threat-actor-sophistication-ov': [
        'none', 'minimal', 'intermediate', 'advanced', 'expert', 'innovator', 'strategic'
    ],
    'tool-type-ov': [
        'denial-of-service', 'exploitation', 'information-gathering',
        'network-capture', 'credential-exploitation', 'remote-access',
        'vulnerability-scanning', 'unknown'
    ],
    'region-ov': [
        'africa', 'eastern-africa', 'middle-africa', 'northern-africa',
        'southern-africa', 'western-africa', 'americas', 'caribbean',
        'central-america', 'latin-america-caribbean', 'northern-america',
        'south-america', 'asia', 'central-asia', 'eastern-asia',
        'southern-asia', 'south-eastern-asia', 'western-asia', 'europe',
        'eastern-europe', 'northern-europe', 'southern-europe', 'western-europe',
        'oceania', 'antarctica', 'australia-new-zealand', 'melanesia',
        'micronesia', 'polynesia'
    ],
    'sectors-ov': [
        'agriculture', 'aerospace', 'automotive', 'chemical', 'commercial',
        'communications', 'construction', 'defense', 'education', 'energy',
        'entertainment', 'financial-services', 'government',
        'government-emergency-services', 'government-local',
        'government-national', 'government-public-services',
        'government-regional', 'healthcare', 'hospitality-leisure',
        'infrastructure', 'insurance', 'manufacturing', 'mining', 'non-profit',
        'pharmaceuticals', 'retail', 'technology', 'telecommunications',
        'transportation', 'utilities', 'water'
    ],
    'relationship-type-ov': [
        'uses', 'targets', 'mitigates', 'indicates', 'attributed-to',
        'communicates-with', 'consists-of', 'controls', 'delivers',
        'detects', 'drops', 'exploits', 'hosts', 'impersonates',
        'located-at', 'owns', 'related-to', 'remediates', 'resolves-to',
        'revoked-by', 'subtechnique-of', 'variant-of'
    ],
    'hash-algorithm-ov': [
        'MD5', 'SHA-1', 'SHA-256', 'SHA-512', 'SHA3-256', 'SHA3-512', 'SSDEEP', 'TLSH'
    ],
    'tlp-ov': [
        'white', 'green', 'amber', 'red', 'amber+strict'
    ]
};

const STIX_COMMON_PROPERTIES = {
    required: [
        { key: 'type', label: 'Type', type: 'string', description: 'STIX object type.' },
        { key: 'spec_version', label: 'Spec Version', type: 'string', description: 'STIX specification version.', default: STIX_VERSION },
        { key: 'id', label: 'ID', type: 'identifier', description: 'STIX identifier.' },
        { key: 'created', label: 'Created', type: 'timestamp', description: 'Creation timestamp.' },
        { key: 'modified', label: 'Modified', type: 'timestamp', description: 'Modified timestamp.' }
    ],
    optional: [
        { key: 'created_by_ref', label: 'Created By', type: 'identifier', description: 'Identity reference.' },
        { key: 'revoked', label: 'Revoked', type: 'boolean', description: 'Whether this object is revoked.' },
        { key: 'labels', label: 'Labels', type: 'list', description: 'Label list.' },
        { key: 'confidence', label: 'Confidence', type: 'integer', description: 'Confidence (0-100).', min: 0, max: 100 },
        { key: 'lang', label: 'Language', type: 'string', description: 'RFC 5646 language tag.' },
        { key: 'external_references', label: 'External References', type: 'external-references', description: 'External references list.' },
        { key: 'object_marking_refs', label: 'Object Markings', type: 'object-marking-refs', description: 'Marking-definition references.' },
        { key: 'granular_markings', label: 'Granular Markings', type: 'granular-markings', description: 'Granular markings list.' }
    ]
};

const STIX_SDO_OBJECTS = {
    'attack-pattern': {
        label: 'Attack Pattern',
        category: 'sdo',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'Name of the attack pattern.' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' },
            { key: 'aliases', label: 'Aliases', type: 'list', description: 'Aliases list.' },
            { key: 'kill_chain_phases', label: 'Kill Chain Phases', type: 'kill-chain-phases', description: 'Kill chain phases.' }
        ]
    },
    'campaign': {
        label: 'Campaign',
        category: 'sdo',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'Campaign name.' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' },
            { key: 'aliases', label: 'Aliases', type: 'list', description: 'Aliases list.' },
            { key: 'first_seen', label: 'First Seen', type: 'timestamp', description: 'First seen time.' },
            { key: 'last_seen', label: 'Last Seen', type: 'timestamp', description: 'Last seen time.' },
            { key: 'objective', label: 'Objective', type: 'text', description: 'Campaign objective.' }
        ]
    },
    'course-of-action': {
        label: 'Course of Action',
        category: 'sdo',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'Course of action name.' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' }
        ]
    },
    'grouping': {
        label: 'Grouping',
        category: 'sdo',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'Grouping name.' },
            { key: 'context', label: 'Context', type: 'enum', description: 'Grouping context.', vocabulary: 'grouping-context-ov' },
            { key: 'object_refs', label: 'Object References', type: 'object-refs', description: 'Referenced object IDs.' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' }
        ]
    },
    'identity': {
        label: 'Identity',
        category: 'sdo',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'Identity name.' },
            { key: 'identity_class', label: 'Identity Class', type: 'enum', description: 'Identity class.', vocabulary: 'identity-class-ov' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' },
            { key: 'roles', label: 'Roles', type: 'list', description: 'Roles list.' },
            { key: 'sectors', label: 'Sectors', type: 'list:open-vocab', description: 'Sectors list.', vocabulary: 'sectors-ov' },
            { key: 'contact_information', label: 'Contact Information', type: 'text', description: 'Contact details.' }
        ]
    },
    'indicator': {
        label: 'Indicator',
        category: 'sdo',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'Indicator name.' },
            { key: 'pattern', label: 'Pattern', type: 'text', description: 'STIX pattern.' },
            { key: 'pattern_type', label: 'Pattern Type', type: 'enum', description: 'Pattern type.', vocabulary: 'pattern-type-ov' },
            { key: 'valid_from', label: 'Valid From', type: 'timestamp', description: 'Valid-from time.' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' },
            { key: 'pattern_version', label: 'Pattern Version', type: 'string', description: 'Pattern version.' },
            { key: 'valid_until', label: 'Valid Until', type: 'timestamp', description: 'Valid-until time.' },
            { key: 'kill_chain_phases', label: 'Kill Chain Phases', type: 'kill-chain-phases', description: 'Kill chain phases.' }
        ]
    },
    'infrastructure': {
        label: 'Infrastructure',
        category: 'sdo',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'Infrastructure name.' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' },
            { key: 'aliases', label: 'Aliases', type: 'list', description: 'Aliases list.' },
            { key: 'infrastructure_types', label: 'Infrastructure Types', type: 'list:open-vocab', description: 'Infrastructure types.', vocabulary: 'infrastructure-type-ov' },
            { key: 'first_seen', label: 'First Seen', type: 'timestamp', description: 'First seen time.' },
            { key: 'last_seen', label: 'Last Seen', type: 'timestamp', description: 'Last seen time.' },
            { key: 'kill_chain_phases', label: 'Kill Chain Phases', type: 'kill-chain-phases', description: 'Kill chain phases.' }
        ]
    },
    'intrusion-set': {
        label: 'Intrusion Set',
        category: 'sdo',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'Intrusion set name.' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' },
            { key: 'aliases', label: 'Aliases', type: 'list', description: 'Aliases list.' },
            { key: 'first_seen', label: 'First Seen', type: 'timestamp', description: 'First seen time.' },
            { key: 'last_seen', label: 'Last Seen', type: 'timestamp', description: 'Last seen time.' },
            { key: 'goals', label: 'Goals', type: 'list', description: 'Goals list.' },
            { key: 'resource_level', label: 'Resource Level', type: 'enum', description: 'Resource level.', vocabulary: 'attack-resource-level-ov' },
            { key: 'primary_motivation', label: 'Primary Motivation', type: 'enum', description: 'Primary motivation.', vocabulary: 'attack-motivation-ov' },
            { key: 'secondary_motivations', label: 'Secondary Motivations', type: 'list:open-vocab', description: 'Secondary motivations.', vocabulary: 'attack-motivation-ov' }
        ]
    },
    'location': {
        label: 'Location',
        category: 'sdo',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'Location name.' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' },
            { key: 'latitude', label: 'Latitude', type: 'number', description: 'Latitude.', min: -90, max: 90 },
            { key: 'longitude', label: 'Longitude', type: 'number', description: 'Longitude.', min: -180, max: 180 },
            { key: 'precision', label: 'Precision', type: 'number', description: 'Precision.' },
            { key: 'region', label: 'Region', type: 'enum', description: 'Region.', vocabulary: 'region-ov' },
            { key: 'country', label: 'Country', type: 'string', description: 'Country.' },
            { key: 'administrative_area', label: 'Administrative Area', type: 'string', description: 'Administrative area.' },
            { key: 'city', label: 'City', type: 'string', description: 'City.' },
            { key: 'postal_code', label: 'Postal Code', type: 'string', description: 'Postal code.' },
            { key: 'street_address', label: 'Street Address', type: 'string', description: 'Street address.' }
        ]
    },
    'malware': {
        label: 'Malware',
        category: 'sdo',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'Malware name.' },
            { key: 'is_family', label: 'Is Family', type: 'boolean', description: 'Whether this is a malware family.' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' },
            { key: 'malware_types', label: 'Malware Types', type: 'list:open-vocab', description: 'Malware types.', vocabulary: 'malware-type-ov' },
            { key: 'aliases', label: 'Aliases', type: 'list', description: 'Aliases list.' },
            { key: 'first_seen', label: 'First Seen', type: 'timestamp', description: 'First seen time.' },
            { key: 'last_seen', label: 'Last Seen', type: 'timestamp', description: 'Last seen time.' },
            { key: 'operating_system_refs', label: 'OS References', type: 'object-refs', description: 'Operating system refs.' },
            { key: 'architecture_execution_envs', label: 'Architectures', type: 'list:open-vocab', description: 'Architectures.', vocabulary: 'processor-architecture-ov' },
            { key: 'implementation_languages', label: 'Implementation Languages', type: 'list:open-vocab', description: 'Implementation languages.', vocabulary: 'implementation-language-ov' },
            { key: 'capabilities', label: 'Capabilities', type: 'list:open-vocab', description: 'Capabilities.', vocabulary: 'malware-capabilities-ov' },
            { key: 'sample_refs', label: 'Sample References', type: 'object-refs', description: 'Sample refs.' },
            { key: 'kill_chain_phases', label: 'Kill Chain Phases', type: 'kill-chain-phases', description: 'Kill chain phases.' }
        ]
    },
    'malware-analysis': {
        label: 'Malware Analysis',
        category: 'sdo',
        required: [
            { key: 'product', label: 'Product', type: 'string', description: 'Analysis product name.' },
            { key: 'analysis_engine_version', label: 'Engine Version', type: 'string', description: 'Analysis engine version.' },
            { key: 'analysis_definition_version', label: 'Definition Version', type: 'string', description: 'Definition version.' },
            { key: 'submitted', label: 'Submitted', type: 'timestamp', description: 'Submission time.' },
            { key: 'analysis_started', label: 'Analysis Started', type: 'timestamp', description: 'Start time.' },
            { key: 'analysis_ended', label: 'Analysis Ended', type: 'timestamp', description: 'End time.' },
            { key: 'result', label: 'Result', type: 'enum', description: 'Analysis result.', vocabulary: 'malware-result-ov' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' },
            { key: 'analysis_sco_refs', label: 'Analysis SCO Refs', type: 'object-refs', description: 'SCO refs.' },
            { key: 'analysis_software_refs', label: 'Analysis Software Refs', type: 'object-refs', description: 'Software refs.' },
            { key: 'analysis_engine_refs', label: 'Engine Refs', type: 'object-refs', description: 'Engine refs.' },
            { key: 'host_vm_refs', label: 'Host VM Refs', type: 'object-refs', description: 'Host VM refs.' },
            { key: 'operating_system_refs', label: 'OS Refs', type: 'object-refs', description: 'OS refs.' },
            { key: 'installed_software_refs', label: 'Installed Software Refs', type: 'object-refs', description: 'Installed software refs.' },
            { key: 'configuration_version', label: 'Configuration Version', type: 'string', description: 'Configuration version.' },
            { key: 'modules', label: 'Modules', type: 'list', description: 'Modules list.' }
        ]
    },
    'note': {
        label: 'Note',
        category: 'sdo',
        required: [
            { key: 'content', label: 'Content', type: 'text', description: 'Note content.' }
        ],
        optional: [
            { key: 'abstract', label: 'Abstract', type: 'text', description: 'Abstract.' },
            { key: 'authors', label: 'Authors', type: 'list', description: 'Author list.' },
            { key: 'object_refs', label: 'Object References', type: 'object-refs', description: 'Referenced objects.' }
        ]
    },
    'observed-data': {
        label: 'Observed Data',
        category: 'sdo',
        required: [
            { key: 'first_observed', label: 'First Observed', type: 'timestamp', description: 'First observed time.' },
            { key: 'last_observed', label: 'Last Observed', type: 'timestamp', description: 'Last observed time.' },
            { key: 'number_observed', label: 'Number Observed', type: 'integer', description: 'Observation count.', min: 0 },
            { key: 'object_refs', label: 'Object References', type: 'object-refs', description: 'Observable object refs.' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' }
        ]
    },
    'opinion': {
        label: 'Opinion',
        category: 'sdo',
        required: [
            { key: 'opinion', label: 'Opinion', type: 'enum', description: 'Opinion value.', vocabulary: 'opinion-enum' },
            { key: 'object_refs', label: 'Object References', type: 'object-refs', description: 'Referenced objects.' }
        ],
        optional: [
            { key: 'explanation', label: 'Explanation', type: 'text', description: 'Explanation.' },
            { key: 'authors', label: 'Authors', type: 'list', description: 'Author list.' }
        ]
    },
    'report': {
        label: 'Report',
        category: 'sdo',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'Report name.' },
            { key: 'published', label: 'Published', type: 'timestamp', description: 'Published time.' },
            { key: 'object_refs', label: 'Object References', type: 'object-refs', description: 'Referenced objects.' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' },
            { key: 'report_types', label: 'Report Types', type: 'list:open-vocab', description: 'Report types.', vocabulary: 'report-type-ov' }
        ]
    },
    'threat-actor': {
        label: 'Threat Actor',
        category: 'sdo',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'Threat actor name.' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' },
            { key: 'aliases', label: 'Aliases', type: 'list', description: 'Aliases list.' },
            { key: 'roles', label: 'Roles', type: 'list:open-vocab', description: 'Roles list.', vocabulary: 'threat-actor-role-ov' },
            { key: 'goals', label: 'Goals', type: 'list', description: 'Goals list.' },
            { key: 'sophistication', label: 'Sophistication', type: 'enum', description: 'Sophistication.', vocabulary: 'threat-actor-sophistication-ov' },
            { key: 'resource_level', label: 'Resource Level', type: 'enum', description: 'Resource level.', vocabulary: 'attack-resource-level-ov' },
            { key: 'primary_motivation', label: 'Primary Motivation', type: 'enum', description: 'Primary motivation.', vocabulary: 'attack-motivation-ov' },
            { key: 'secondary_motivations', label: 'Secondary Motivations', type: 'list:open-vocab', description: 'Secondary motivations.', vocabulary: 'attack-motivation-ov' },
            { key: 'personal_motivations', label: 'Personal Motivations', type: 'list:open-vocab', description: 'Personal motivations.', vocabulary: 'attack-motivation-ov' },
            { key: 'first_seen', label: 'First Seen', type: 'timestamp', description: 'First seen time.' },
            { key: 'last_seen', label: 'Last Seen', type: 'timestamp', description: 'Last seen time.' },
            { key: 'threat_actor_types', label: 'Threat Actor Types', type: 'list:open-vocab', description: 'Threat actor types.', vocabulary: 'threat-actor-type-ov' }
        ]
    },
    'tool': {
        label: 'Tool',
        category: 'sdo',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'Tool name.' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' },
            { key: 'tool_types', label: 'Tool Types', type: 'list:open-vocab', description: 'Tool types.', vocabulary: 'tool-type-ov' },
            { key: 'aliases', label: 'Aliases', type: 'list', description: 'Aliases list.' },
            { key: 'kill_chain_phases', label: 'Kill Chain Phases', type: 'kill-chain-phases', description: 'Kill chain phases.' },
            { key: 'tool_version', label: 'Tool Version', type: 'string', description: 'Tool version.' }
        ]
    },
    'vulnerability': {
        label: 'Vulnerability',
        category: 'sdo',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'Vulnerability name.' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' }
        ]
    }
};

const STIX_EXTENSION_DEFINITION = {
    label: 'Extension Definition',
    category: 'extension',
    required: [
        { key: 'name', label: 'Name', type: 'string', description: 'Extension name.' },
        { key: 'description', label: 'Description', type: 'text', description: 'Extension description.' },
        { key: 'schema', label: 'Schema', type: 'string', description: 'Schema URL.' },
        { key: 'version', label: 'Version', type: 'string', description: 'Extension version.' },
        { key: 'extension_types', label: 'Extension Types', type: 'list', description: 'Extension types list.' }
    ],
    optional: [
        { key: 'created_by_ref', label: 'Created By', type: 'identifier', description: 'Identity reference.' }
    ]
};

const STIX_SRO_OBJECTS = {
    'relationship': {
        label: 'Relationship',
        category: 'sro',
        required: [
            { key: 'relationship_type', label: 'Relationship Type', type: 'open-vocab', description: 'Relationship type.', vocabulary: 'relationship-type-ov' },
            { key: 'source_ref', label: 'Source Ref', type: 'identifier', description: 'Source object ID.' },
            { key: 'target_ref', label: 'Target Ref', type: 'identifier', description: 'Target object ID.' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' },
            { key: 'start_time', label: 'Start Time', type: 'timestamp', description: 'Start time.' },
            { key: 'stop_time', label: 'Stop Time', type: 'timestamp', description: 'Stop time.' }
        ]
    },
    'sighting': {
        label: 'Sighting',
        category: 'sro',
        required: [
            { key: 'sighting_of_ref', label: 'Sighting Of', type: 'identifier', description: 'Sighting object ID.' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'Description.' },
            { key: 'observed_data_refs', label: 'Observed Data Refs', type: 'object-refs', description: 'Observed data refs.' },
            { key: 'where_sighted_refs', label: 'Where Sighted Refs', type: 'object-refs', description: 'Where sighted refs.' },
            { key: 'summary', label: 'Summary', type: 'boolean', description: 'Summary flag.' },
            { key: 'count', label: 'Count', type: 'integer', description: 'Count.', min: 0 },
            { key: 'first_seen', label: 'First Seen', type: 'timestamp', description: 'First seen time.' },
            { key: 'last_seen', label: 'Last Seen', type: 'timestamp', description: 'Last seen time.' }
        ]
    }
};

const STIX_SCO_OBJECTS = {
    'artifact': {
        label: 'Artifact',
        category: 'sco',
        required: [],
        optional: [
            { key: 'mime_type', label: 'MIME Type', type: 'string', description: 'MIME type.' },
            { key: 'payload_bin', label: 'Payload (Binary)', type: 'text', description: 'Base64 payload.' },
            { key: 'url', label: 'URL', type: 'string', description: 'Artifact URL.' },
            { key: 'hashes', label: 'Hashes', type: 'hashes', description: 'Hashes dictionary.' },
            { key: 'encryption_algorithm', label: 'Encryption Algorithm', type: 'string', description: 'Encryption algorithm.' },
            { key: 'decryption_key', label: 'Decryption Key', type: 'string', description: 'Decryption key.' }
        ]
    },
    'autonomous-system': {
        label: 'Autonomous System',
        category: 'sco',
        required: [
            { key: 'number', label: 'Number', type: 'integer', description: 'AS number.' }
        ],
        optional: [
            { key: 'name', label: 'Name', type: 'string', description: 'AS name.' },
            { key: 'rir', label: 'RIR', type: 'string', description: 'RIR.' }
        ]
    },
    'directory': {
        label: 'Directory',
        category: 'sco',
        required: [
            { key: 'path', label: 'Path', type: 'string', description: 'Directory path.' }
        ],
        optional: [
            { key: 'path_enc', label: 'Path Encoding', type: 'string', description: 'Path encoding.' },
            { key: 'created', label: 'Created', type: 'timestamp', description: 'Created time.' },
            { key: 'modified', label: 'Modified', type: 'timestamp', description: 'Modified time.' },
            { key: 'accessed', label: 'Accessed', type: 'timestamp', description: 'Accessed time.' },
            { key: 'contains_refs', label: 'Contains Refs', type: 'object-refs', description: 'Contains refs.' }
        ]
    },
    'domain-name': {
        label: 'Domain Name',
        category: 'sco',
        required: [
            { key: 'value', label: 'Value', type: 'string', description: 'Domain name.' }
        ],
        optional: [
            { key: 'resolves_to_refs', label: 'Resolves To', type: 'object-refs', description: 'Resolves to refs.' }
        ]
    },
    'email-addr': {
        label: 'Email Address',
        category: 'sco',
        required: [
            { key: 'value', label: 'Value', type: 'string', description: 'Email address.' }
        ],
        optional: [
            { key: 'display_name', label: 'Display Name', type: 'string', description: 'Display name.' },
            { key: 'belongs_to_ref', label: 'Belongs To', type: 'identifier', description: 'Belongs to ref.' }
        ]
    },
    'email-message': {
        label: 'Email Message',
        category: 'sco',
        required: [
            { key: 'is_multipart', label: 'Is Multipart', type: 'boolean', description: 'Multipart flag.' }
        ],
        optional: [
            { key: 'date', label: 'Date', type: 'timestamp', description: 'Date.' },
            { key: 'content_type', label: 'Content Type', type: 'string', description: 'Content type.' },
            { key: 'from_ref', label: 'From', type: 'identifier', description: 'From ref.' },
            { key: 'sender_ref', label: 'Sender', type: 'identifier', description: 'Sender ref.' },
            { key: 'to_refs', label: 'To', type: 'object-refs', description: 'To refs.' },
            { key: 'cc_refs', label: 'CC', type: 'object-refs', description: 'CC refs.' },
            { key: 'bcc_refs', label: 'BCC', type: 'object-refs', description: 'BCC refs.' },
            { key: 'subject', label: 'Subject', type: 'string', description: 'Subject.' },
            { key: 'received_lines', label: 'Received Lines', type: 'list', description: 'Received lines.' },
            { key: 'additional_header_fields', label: 'Additional Headers', type: 'dictionary', description: 'Header fields.' },
            { key: 'body', label: 'Body', type: 'text', description: 'Body.' },
            { key: 'body_multipart', label: 'Multipart Body', type: 'dictionary', description: 'Multipart body.' },
            { key: 'raw_email_ref', label: 'Raw Email Ref', type: 'identifier', description: 'Raw email ref.' }
        ]
    },
    'file': {
        label: 'File',
        category: 'sco',
        required: [],
        optional: [
            { key: 'extensions', label: 'Extensions', type: 'extensions', description: 'File extensions.' },
            { key: 'hashes', label: 'Hashes', type: 'hashes', description: 'Hashes dictionary.' },
            { key: 'size', label: 'Size', type: 'integer', description: 'File size.' },
            { key: 'name', label: 'Name', type: 'string', description: 'File name.' },
            { key: 'name_enc', label: 'Name Encoding', type: 'string', description: 'Name encoding.' },
            { key: 'magic_number_hex', label: 'Magic Number', type: 'string', description: 'Magic number (hex).' },
            { key: 'mime_type', label: 'MIME Type', type: 'string', description: 'MIME type.' },
            { key: 'created', label: 'Created', type: 'timestamp', description: 'Created time.' },
            { key: 'modified', label: 'Modified', type: 'timestamp', description: 'Modified time.' },
            { key: 'accessed', label: 'Accessed', type: 'timestamp', description: 'Accessed time.' },
            { key: 'parent_directory_ref', label: 'Parent Directory', type: 'identifier', description: 'Parent directory ref.' },
            { key: 'contains_refs', label: 'Contains Refs', type: 'object-refs', description: 'Contains refs.' },
            { key: 'content_ref', label: 'Content Ref', type: 'identifier', description: 'Content ref.' }
        ]
    },
    'ipv4-addr': {
        label: 'IPv4 Address',
        category: 'sco',
        required: [
            { key: 'value', label: 'Value', type: 'string', description: 'IPv4 address.' }
        ],
        optional: [
            { key: 'resolves_to_refs', label: 'Resolves To', type: 'object-refs', description: 'Resolves to refs.' },
            { key: 'belongs_to_refs', label: 'Belongs To', type: 'object-refs', description: 'Belongs to refs.' }
        ]
    },
    'ipv6-addr': {
        label: 'IPv6 Address',
        category: 'sco',
        required: [
            { key: 'value', label: 'Value', type: 'string', description: 'IPv6 address.' }
        ],
        optional: [
            { key: 'resolves_to_refs', label: 'Resolves To', type: 'object-refs', description: 'Resolves to refs.' },
            { key: 'belongs_to_refs', label: 'Belongs To', type: 'object-refs', description: 'Belongs to refs.' }
        ]
    },
    'mac-addr': {
        label: 'MAC Address',
        category: 'sco',
        required: [
            { key: 'value', label: 'Value', type: 'string', description: 'MAC address.' }
        ],
        optional: []
    },
    'mutex': {
        label: 'Mutex',
        category: 'sco',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'Mutex name.' }
        ],
        optional: []
    },
    'network-traffic': {
        label: 'Network Traffic',
        category: 'sco',
        required: [
            { key: 'protocols', label: 'Protocols', type: 'list', description: 'Protocols list.' }
        ],
        optional: [
            { key: 'src_ref', label: 'Source Ref', type: 'identifier', description: 'Source ref.' },
            { key: 'dst_ref', label: 'Destination Ref', type: 'identifier', description: 'Destination ref.' },
            { key: 'src_port', label: 'Source Port', type: 'integer', description: 'Source port.', min: 0, max: 65535 },
            { key: 'dst_port', label: 'Destination Port', type: 'integer', description: 'Destination port.', min: 0, max: 65535 },
            { key: 'start', label: 'Start', type: 'timestamp', description: 'Start time.' },
            { key: 'end', label: 'End', type: 'timestamp', description: 'End time.' },
            { key: 'is_active', label: 'Is Active', type: 'boolean', description: 'Is active.' },
            { key: 'src_byte_count', label: 'Source Byte Count', type: 'integer', description: 'Source bytes.', min: 0 },
            { key: 'dst_byte_count', label: 'Destination Byte Count', type: 'integer', description: 'Destination bytes.', min: 0 },
            { key: 'src_packets', label: 'Source Packets', type: 'integer', description: 'Source packets.', min: 0 },
            { key: 'dst_packets', label: 'Destination Packets', type: 'integer', description: 'Destination packets.', min: 0 },
            { key: 'encapsulates_refs', label: 'Encapsulates Refs', type: 'object-refs', description: 'Encapsulates refs.' },
            { key: 'encapsulated_by_ref', label: 'Encapsulated By', type: 'identifier', description: 'Encapsulated by ref.' },
            { key: 'extensions', label: 'Extensions', type: 'extensions', description: 'Extensions.' }
        ]
    },
    'process': {
        label: 'Process',
        category: 'sco',
        required: [],
        optional: [
            { key: 'is_hidden', label: 'Is Hidden', type: 'boolean', description: 'Is hidden.' },
            { key: 'pid', label: 'PID', type: 'integer', description: 'Process ID.' },
            { key: 'created_time', label: 'Created Time', type: 'timestamp', description: 'Created time.' },
            { key: 'cwd', label: 'CWD', type: 'string', description: 'Current working directory.' },
            { key: 'command_line', label: 'Command Line', type: 'string', description: 'Command line.' },
            { key: 'environment_variables', label: 'Environment Variables', type: 'dictionary', description: 'Environment variables.' },
            { key: 'opened_connection_refs', label: 'Opened Connection Refs', type: 'object-refs', description: 'Opened connections.' },
            { key: 'creator_user_ref', label: 'Creator User Ref', type: 'identifier', description: 'Creator user ref.' },
            { key: 'image_ref', label: 'Image Ref', type: 'identifier', description: 'Image ref.' },
            { key: 'parent_ref', label: 'Parent Ref', type: 'identifier', description: 'Parent ref.' },
            { key: 'child_refs', label: 'Child Refs', type: 'object-refs', description: 'Child refs.' }
        ]
    },
    'software': {
        label: 'Software',
        category: 'sco',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'Software name.' }
        ],
        optional: [
            { key: 'cpe', label: 'CPE', type: 'string', description: 'CPE string.' },
            { key: 'swid', label: 'SWID', type: 'string', description: 'SWID tag.' },
            { key: 'vendor', label: 'Vendor', type: 'string', description: 'Vendor.' },
            { key: 'version', label: 'Version', type: 'string', description: 'Version.' },
            { key: 'languages', label: 'Languages', type: 'list', description: 'Languages.' }
        ]
    },
    'url': {
        label: 'URL',
        category: 'sco',
        required: [
            { key: 'value', label: 'Value', type: 'string', description: 'URL.' }
        ],
        optional: []
    },
    'user-account': {
        label: 'User Account',
        category: 'sco',
        required: [
            { key: 'user_id', label: 'User ID', type: 'string', description: 'User ID.' }
        ],
        optional: [
            { key: 'account_login', label: 'Account Login', type: 'string', description: 'Account login.' },
            { key: 'account_type', label: 'Account Type', type: 'string', description: 'Account type.' },
            { key: 'display_name', label: 'Display Name', type: 'string', description: 'Display name.' },
            { key: 'is_service_account', label: 'Is Service Account', type: 'boolean', description: 'Service account flag.' },
            { key: 'is_privileged', label: 'Is Privileged', type: 'boolean', description: 'Privileged flag.' },
            { key: 'can_escalate_privs', label: 'Can Escalate Privs', type: 'boolean', description: 'Can escalate privs.' },
            { key: 'is_disabled', label: 'Is Disabled', type: 'boolean', description: 'Disabled flag.' },
            { key: 'account_created', label: 'Account Created', type: 'timestamp', description: 'Account created.' },
            { key: 'account_expires', label: 'Account Expires', type: 'timestamp', description: 'Account expires.' },
            { key: 'password_last_changed', label: 'Password Last Changed', type: 'timestamp', description: 'Password last changed.' },
            { key: 'account_first_login', label: 'Account First Login', type: 'timestamp', description: 'First login.' },
            { key: 'account_last_login', label: 'Account Last Login', type: 'timestamp', description: 'Last login.' }
        ]
    },
    'windows-registry-key': {
        label: 'Windows Registry Key',
        category: 'sco',
        required: [
            { key: 'key', label: 'Key', type: 'string', description: 'Registry key.' }
        ],
        optional: [
            { key: 'values', label: 'Values', type: 'dictionary', description: 'Registry values.' },
            { key: 'modified', label: 'Modified', type: 'timestamp', description: 'Modified time.' },
            { key: 'creator_user_ref', label: 'Creator User Ref', type: 'identifier', description: 'Creator user ref.' },
            { key: 'number_of_subkeys', label: 'Number of Subkeys', type: 'integer', description: 'Subkey count.', min: 0 }
        ]
    },
    'x509-certificate': {
        label: 'X.509 Certificate',
        category: 'sco',
        required: [
            { key: 'is_self_signed', label: 'Is Self Signed', type: 'boolean', description: 'Self-signed flag.' },
            { key: 'subject', label: 'Subject', type: 'string', description: 'Subject.' },
            { key: 'issuer', label: 'Issuer', type: 'string', description: 'Issuer.' },
            { key: 'validity_not_before', label: 'Validity Not Before', type: 'timestamp', description: 'Not-before time.' },
            { key: 'validity_not_after', label: 'Validity Not After', type: 'timestamp', description: 'Not-after time.' },
            { key: 'serial_number', label: 'Serial Number', type: 'string', description: 'Serial number.' }
        ],
        optional: [
            { key: 'signature_algorithm', label: 'Signature Algorithm', type: 'string', description: 'Signature algorithm.' },
            { key: 'version', label: 'Version', type: 'string', description: 'Version.' },
            { key: 'hashes', label: 'Hashes', type: 'hashes', description: 'Hashes dictionary.' }
        ]
    }
};

const STIX_MARKING_DEFINITIONS = {
    'marking-definition': {
        label: 'Marking Definition',
        category: 'marking',
        required: [
            { key: 'definition_type', label: 'Definition Type', type: 'enum', description: 'Definition type.', options: ['tlp', 'statement'] },
            { key: 'definition', label: 'Definition', type: 'marking-definition', description: 'Definition object.' }
        ],
        optional: []
    }
};

const STIX_OBJECT_DEFS = Object.assign(
    {},
    STIX_SDO_OBJECTS,
    STIX_SRO_OBJECTS,
    STIX_SCO_OBJECTS,
    STIX_MARKING_DEFINITIONS,
    { 'extension-definition': STIX_EXTENSION_DEFINITION }
);

const STIX_SCHEMA = {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    title: 'STIX 2.1 Bundle',
    type: 'object',
    required: ['type', 'id', 'spec_version', 'objects'],
    properties: {
        type: { const: 'bundle' },
        id: { type: 'string', pattern: STIX_ID_PATTERN.source },
        spec_version: { const: STIX_VERSION },
        objects: {
            type: 'array',
            items: {
                oneOf: Object.keys(STIX_OBJECT_DEFS).map((key) => ({ $ref: '#/definitions/' + key }))
            }
        }
    },
    definitions: {}
};

(function buildSchemaDefinitions() {
    const defs = STIX_SCHEMA.definitions;
    const baseProps = {
        type: { type: 'string' },
        spec_version: { type: 'string' },
        id: { type: 'string', pattern: STIX_ID_PATTERN.source }
    };

    Object.entries(STIX_OBJECT_DEFS).forEach(([type, def]) => {
        const schema = {
            type: 'object',
            required: ['type'],
            properties: { ...baseProps, type: { const: type } }
        };
        defs[type] = schema;
    });
})();

function getStixObjectDefinition(type) {
    return STIX_OBJECT_DEFS[type] || null;
}

function getVocabulary(key) {
    return STIX_VOCABULARIES[key] || [];
}

if (typeof window !== 'undefined') {
    window.STIX_VERSION = STIX_VERSION;
    window.STIX_ID_PATTERN = STIX_ID_PATTERN;
    window.STIX_KILL_CHAIN_PHASES = STIX_KILL_CHAIN_PHASES;
    window.STIX_VOCABULARIES = STIX_VOCABULARIES;
    window.STIX_COMMON_PROPERTIES = STIX_COMMON_PROPERTIES;
    window.STIX_OBJECT_DEFS = STIX_OBJECT_DEFS;
    window.STIX_SCHEMA = STIX_SCHEMA;
    window.getStixObjectDefinition = getStixObjectDefinition;
    window.getVocabulary = getVocabulary;
}

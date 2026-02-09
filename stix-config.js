/**
 * STIX 2.1 Object Configuration
 *
 * Defines every SDO (STIX Domain Object) type used by AttackFlow together with
 * its required and optional properties per the STIX 2.1 specification
 * (OASIS Standard, 10 June 2021 — https://docs.oasis-open.org/cti/stix/v2.1/).
 *
 * Each entry in STIX_OBJECTS carries:
 *   - label         Human-readable name shown in the UI
 *   - description   Short summary of the SDO's purpose
 *   - stixSpec      URL to the relevant spec section
 *   - required      Fields the spec mandates (beyond the Common Properties)
 *   - optional      Fields the spec allows (beyond the Common Properties)
 *   - vocabularies  Open vocabulary values used by enum-type fields
 *
 * Common Properties present on ALL SDOs (§3.1) are listed separately in
 * STIX_COMMON_PROPERTIES and are not repeated per type.
 *
 * Field descriptor format:
 *   { key, label, type, description, vocabulary?, pattern?, placeholder? }
 *
 * Supported field types:
 *   string        Free-form text
 *   text          Multi-line text (textarea)
 *   identifier    STIX ID (auto-generated, type--uuid)
 *   timestamp     ISO 8601 date-time
 *   enum          Single value from a vocabulary
 *   open-vocab    Single value from a vocabulary, but user may provide custom
 *   list          Ordered list of strings
 *   list:open-vocab  Ordered list drawn from a vocabulary
 *   integer       Whole number
 *   boolean       true / false
 *   kill-chain-phases  Array of { kill_chain_name, phase_name }
 *   external-references  Array of STIX external-reference objects
 *   dictionary    Key/value pairs
 */

'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// STIX 2.1 Common Properties (§3.1) — present on every SDO
// ─────────────────────────────────────────────────────────────────────────────
const STIX_COMMON_PROPERTIES = {
    required: [
        { key: 'type',            label: 'Type',            type: 'string',     description: 'The SDO type identifier (e.g. "malware").' },
        { key: 'spec_version',    label: 'Spec Version',    type: 'string',     description: 'STIX specification version. Must be "2.1".', default: '2.1' },
        { key: 'id',              label: 'ID',              type: 'identifier',  description: 'Globally unique STIX identifier (type--UUIDv4).' },
        { key: 'created',         label: 'Created',         type: 'timestamp',  description: 'Time at which the object was originally created.' },
        { key: 'modified',        label: 'Modified',        type: 'timestamp',  description: 'Time at which this version of the object was last modified.' }
    ],
    optional: [
        { key: 'created_by_ref',       label: 'Created By',           type: 'identifier',            description: 'ID of the identity that created this object.' },
        { key: 'revoked',              label: 'Revoked',              type: 'boolean',               description: 'Whether this object has been revoked.' },
        { key: 'labels',               label: 'Labels',               type: 'list',                  description: 'Set of descriptive labels/tags.' },
        { key: 'confidence',           label: 'Confidence',           type: 'integer',               description: 'Confidence in the correctness of this object (0-100).' },
        { key: 'lang',                 label: 'Language',             type: 'string',                description: 'Language of the text content (RFC 5646).' },
        { key: 'external_references',  label: 'External References',  type: 'external-references',   description: 'List of external references (URLs, source names).' },
        { key: 'object_marking_refs',  label: 'Markings',            type: 'list',                  description: 'List of marking-definition IDs that apply.' },
        { key: 'granular_markings',    label: 'Granular Markings',    type: 'list',                  description: 'Granular markings applied to specific fields.' }
    ]
};

// ─────────────────────────────────────────────────────────────────────────────
// Open Vocabulary definitions (§10) referenced by SDO fields
// ─────────────────────────────────────────────────────────────────────────────
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
        'screen-capture', 'spyware', 'trojan', 'unknown', 'virus', 'webshell', 'wiper', 'worm'
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
    ]
};

// ─────────────────────────────────────────────────────────────────────────────
// SDO Type Definitions (§4 – §12)
// ─────────────────────────────────────────────────────────────────────────────
const STIX_OBJECTS = {

    // §4.2 Attack Pattern
    'attack-pattern': {
        label: 'Attack Pattern',
        description: 'A type of TTP that describes ways threat actors attempt to compromise targets.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_axjijf603msy',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'The name used to identify the attack pattern.', placeholder: 'e.g. Spear Phishing' }
        ],
        optional: [
            { key: 'description',          label: 'Description',          type: 'text',                  description: 'A description that provides more details and context.' },
            { key: 'aliases',              label: 'Aliases',              type: 'list',                  description: 'Alternative names used to identify this attack pattern.' },
            { key: 'kill_chain_phases',    label: 'Kill Chain Phases',    type: 'kill-chain-phases',     description: 'The kill chain phase(s) to which this attack pattern corresponds.' },
            { key: 'external_references',  label: 'External References',  type: 'external-references',   description: 'External references for this attack pattern.' }
        ]
    },

    // §4.3 Campaign
    'campaign': {
        label: 'Campaign',
        description: 'A grouping of adversarial behaviors describing a set of malicious activities or attacks occurring over a period of time against a specific set of targets.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_pcpvfz4ik6d6',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'A name used to identify the campaign.', placeholder: 'e.g. Operation Aurora' }
        ],
        optional: [
            { key: 'description',   label: 'Description',    type: 'text',       description: 'A description providing more campaign details.' },
            { key: 'aliases',       label: 'Aliases',         type: 'list',       description: 'Alternative names for this campaign.' },
            { key: 'first_seen',    label: 'First Seen',      type: 'timestamp',  description: 'The time the campaign was first seen.' },
            { key: 'last_seen',     label: 'Last Seen',       type: 'timestamp',  description: 'The time the campaign was last seen.' },
            { key: 'objective',     label: 'Objective',        type: 'text',       description: 'The campaign\'s primary objective.' }
        ]
    },

    // §4.4 Course of Action
    'course-of-action': {
        label: 'Course of Action',
        description: 'A recommendation from a producer to a consumer on the actions to take in response to a threat.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_a925mpw39txn',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'A name used to identify the course of action.', placeholder: 'e.g. Block Traffic to C2' }
        ],
        optional: [
            { key: 'description', label: 'Description', type: 'text', description: 'A description providing more details about the course of action.' }
        ]
    },

    // §4.5 Grouping
    'grouping': {
        label: 'Grouping',
        description: 'Explicitly defines a shared context for the referenced STIX Objects.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_t56pn0cv3jjk',
        required: [
            { key: 'name',    label: 'Name',    type: 'string',     description: 'A name for this grouping.' },
            { key: 'context',  label: 'Context', type: 'open-vocab', description: 'A short descriptor of the shared context.', vocabulary: 'grouping-context-ov' }
        ],
        optional: [
            { key: 'description',   label: 'Description',    type: 'text', description: 'A description providing more context about the grouped objects.' },
            { key: 'object_refs',   label: 'Object Refs',    type: 'list', description: 'The STIX Objects that are referred to by this grouping.' }
        ]
    },

    // §4.6 Identity
    'identity': {
        label: 'Identity',
        description: 'Actual individuals, organizations, or groups, as well as classes of individuals, organizations, or groups.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_wh296fiwpklp',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'The name of this identity.', placeholder: 'e.g. ACME Corporation' }
        ],
        optional: [
            { key: 'description',     label: 'Description',      type: 'text',          description: 'A description of the identity.' },
            { key: 'roles',           label: 'Roles',             type: 'list',          description: 'The roles this identity performs (e.g. CEO).' },
            { key: 'identity_class',  label: 'Identity Class',    type: 'open-vocab',    description: 'The type of entity (individual, group, organization, etc.).', vocabulary: 'identity-class-ov' },
            { key: 'sectors',         label: 'Sectors',            type: 'list:open-vocab', description: 'The industry sectors this identity belongs to.', vocabulary: 'sectors-ov' },
            { key: 'contact_information', label: 'Contact Info',  type: 'text',          description: 'Contact information for this identity.' }
        ]
    },

    // §4.7 Indicator
    'indicator': {
        label: 'Indicator',
        description: 'Contains a pattern that can be used to detect suspicious or malicious cyber activity.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_muftrcpnf89v',
        required: [
            { key: 'name',          label: 'Name',           type: 'string',     description: 'A name for this indicator.', placeholder: 'e.g. Malicious File Hash' },
            { key: 'pattern',       label: 'Pattern',         type: 'text',       description: 'The detection pattern (e.g. STIX Patterning).', placeholder: "[file:hashes.'SHA-256' = '...']" },
            { key: 'pattern_type',  label: 'Pattern Type',    type: 'open-vocab', description: 'The pattern language used.', vocabulary: 'pattern-type-ov' },
            { key: 'valid_from',    label: 'Valid From',       type: 'timestamp',  description: 'The time from which this indicator is considered valid.' }
        ],
        optional: [
            { key: 'description',       label: 'Description',       type: 'text',              description: 'A description providing more details.' },
            { key: 'indicator_types',   label: 'Indicator Types',   type: 'list:open-vocab',   description: 'Classification for this indicator.', vocabulary: 'indicator-type-ov' },
            { key: 'valid_until',       label: 'Valid Until',        type: 'timestamp',         description: 'Expiration time for this indicator.' },
            { key: 'kill_chain_phases', label: 'Kill Chain Phases',  type: 'kill-chain-phases', description: 'The kill chain phase(s) this indicator detects.' },
            { key: 'pattern_version',   label: 'Pattern Version',   type: 'string',            description: 'The version of the pattern language used.' }
        ]
    },

    // §4.8 Infrastructure
    'infrastructure': {
        label: 'Infrastructure',
        description: 'Represents a type of TTP and describes systems, software services, and associated physical or virtual resources.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_jo3k1o6lr9',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'A name or characterizing text for this infrastructure.', placeholder: 'e.g. Cobalt Strike Server' }
        ],
        optional: [
            { key: 'description',          label: 'Description',          type: 'text',              description: 'A description providing more details.' },
            { key: 'infrastructure_types', label: 'Infrastructure Types', type: 'list:open-vocab',   description: 'The type of infrastructure.', vocabulary: 'infrastructure-type-ov' },
            { key: 'aliases',              label: 'Aliases',              type: 'list',              description: 'Alternative names for this infrastructure.' },
            { key: 'kill_chain_phases',    label: 'Kill Chain Phases',    type: 'kill-chain-phases', description: 'The kill chain phase(s) this infrastructure is used in.' },
            { key: 'first_seen',           label: 'First Seen',           type: 'timestamp',         description: 'First time observed.' },
            { key: 'last_seen',            label: 'Last Seen',            type: 'timestamp',         description: 'Last time observed.' }
        ]
    },

    // §4.9 Intrusion Set
    'intrusion-set': {
        label: 'Intrusion Set',
        description: 'A grouped set of adversarial behaviors and resources with common properties believed to be orchestrated by a single organization.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_5ol9xlbmgu1l',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'A name for this intrusion set.', placeholder: 'e.g. APT29' }
        ],
        optional: [
            { key: 'description',       label: 'Description',        type: 'text',              description: 'More details and context.' },
            { key: 'aliases',           label: 'Aliases',             type: 'list',              description: 'Alternative names (e.g. Cozy Bear, The Dukes).' },
            { key: 'first_seen',        label: 'First Seen',          type: 'timestamp',         description: 'Earliest known activity.' },
            { key: 'last_seen',         label: 'Last Seen',           type: 'timestamp',         description: 'Most recent known activity.' },
            { key: 'goals',             label: 'Goals',                type: 'list',              description: 'High-level goals of this intrusion set.' },
            { key: 'resource_level',    label: 'Resource Level',      type: 'open-vocab',        description: 'Organizational level at which this operates.', vocabulary: 'attack-resource-level-ov' },
            { key: 'primary_motivation', label: 'Primary Motivation', type: 'open-vocab',        description: 'Primary reason or motivation.', vocabulary: 'attack-motivation-ov' },
            { key: 'secondary_motivations', label: 'Secondary Motivations', type: 'list:open-vocab', description: 'Additional motivations.', vocabulary: 'attack-motivation-ov' }
        ]
    },

    // §4.10 Location
    'location': {
        label: 'Location',
        description: 'Represents a geographic location.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_th8nitr8jb4k',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'A name for this location.', placeholder: 'e.g. Eastern Europe' }
        ],
        optional: [
            { key: 'description',         label: 'Description',          type: 'text',       description: 'A textual description of the location.' },
            { key: 'latitude',            label: 'Latitude',              type: 'string',     description: 'Latitude in decimal degrees (WGS 84).' },
            { key: 'longitude',           label: 'Longitude',             type: 'string',     description: 'Longitude in decimal degrees (WGS 84).' },
            { key: 'precision',           label: 'Precision',             type: 'string',     description: 'Accuracy of lat/long coordinates in metres.' },
            { key: 'region',              label: 'Region',                type: 'open-vocab', description: 'UN M49 region.', vocabulary: 'region-ov' },
            { key: 'country',             label: 'Country',               type: 'string',     description: 'ISO 3166-1 ALPHA-2 country code.' },
            { key: 'administrative_area', label: 'Administrative Area',   type: 'string',     description: 'State/province/region.' },
            { key: 'city',                label: 'City',                  type: 'string',     description: 'City name.' },
            { key: 'street_address',      label: 'Street Address',        type: 'string',     description: 'Street address.' },
            { key: 'postal_code',         label: 'Postal Code',           type: 'string',     description: 'Postal code.' }
        ]
    },

    // §4.11 Malware
    'malware': {
        label: 'Malware',
        description: 'A type of TTP — also known as malicious code and malicious software — used to compromise the confidentiality, integrity, or availability of a victim\'s data or system.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_s5l7katgbp09',
        required: [
            { key: 'name',        label: 'Name',         type: 'string',  description: 'A name used to identify the malware.', placeholder: 'e.g. Emotet' },
            { key: 'is_family',   label: 'Is Family',     type: 'boolean', description: 'Whether this represents a malware family (true) or instance (false).' }
        ],
        optional: [
            { key: 'description',              label: 'Description',              type: 'text',              description: 'Detailed description.' },
            { key: 'malware_types',            label: 'Malware Types',            type: 'list:open-vocab',   description: 'Category of malware.', vocabulary: 'malware-type-ov' },
            { key: 'aliases',                  label: 'Aliases',                  type: 'list',              description: 'Alternative names.' },
            { key: 'first_seen',               label: 'First Seen',               type: 'timestamp',         description: 'First time observed.' },
            { key: 'last_seen',                label: 'Last Seen',                type: 'timestamp',         description: 'Last time observed.' },
            { key: 'operating_system_refs',    label: 'Operating Systems',        type: 'list',              description: 'Operating systems the malware runs on.' },
            { key: 'architecture_execution_envs', label: 'Architectures',         type: 'list:open-vocab',   description: 'Processor architectures the malware targets.', vocabulary: 'processor-architecture-ov' },
            { key: 'implementation_languages', label: 'Implementation Languages', type: 'list:open-vocab',   description: 'Languages used to implement.', vocabulary: 'implementation-language-ov' },
            { key: 'capabilities',             label: 'Capabilities',             type: 'list:open-vocab',   description: 'Known capabilities.', vocabulary: 'malware-capabilities-ov' },
            { key: 'sample_refs',              label: 'Sample Refs',              type: 'list',              description: 'References to associated malware samples.' },
            { key: 'kill_chain_phases',        label: 'Kill Chain Phases',        type: 'kill-chain-phases', description: 'Kill chain phases.' }
        ]
    },

    // §4.12 Malware Analysis
    'malware-analysis': {
        label: 'Malware Analysis',
        description: 'Captures the metadata and results of a particular static or dynamic analysis performed on a malware instance or family.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_6hdrixb3ua4j',
        required: [
            { key: 'product',  label: 'Product',  type: 'string', description: 'The name of the analysis engine or product used.', placeholder: 'e.g. VirusTotal' },
            { key: 'result',   label: 'Result',    type: 'open-vocab', description: 'Classification result.', vocabulary: 'malware-result-ov' }
        ],
        optional: [
            { key: 'version',                label: 'Version',                type: 'string',    description: 'Version of the analysis product.' },
            { key: 'host_vm_ref',            label: 'Host VM Ref',            type: 'string',    description: 'Description of the virtual machine host.' },
            { key: 'operating_system_ref',   label: 'Operating System',       type: 'string',    description: 'Operating system used for the analysis.' },
            { key: 'installed_software_refs', label: 'Installed Software',    type: 'list',      description: 'Other software installed on the analysis environment.' },
            { key: 'configuration_version',  label: 'Config Version',         type: 'string',    description: 'Configuration version of the analysis tool.' },
            { key: 'modules',                label: 'Modules',                type: 'list',      description: 'Specific analysis modules that were used.' },
            { key: 'analysis_engine_version', label: 'Engine Version',        type: 'string',    description: 'The version of the analysis engine.' },
            { key: 'analysis_definition_version', label: 'Definition Version', type: 'string',   description: 'The version of the analysis definitions.' },
            { key: 'submitted',              label: 'Submitted',               type: 'timestamp', description: 'Time the malware was submitted for analysis.' },
            { key: 'analysis_started',       label: 'Analysis Started',        type: 'timestamp', description: 'Time the analysis started.' },
            { key: 'analysis_ended',         label: 'Analysis Ended',          type: 'timestamp', description: 'Time the analysis ended.' },
            { key: 'result_name',            label: 'Result Name',             type: 'string',    description: 'Classification name (e.g. the specific malware family).' },
            { key: 'sample_ref',             label: 'Sample Ref',              type: 'string',    description: 'The malware instance that was analyzed.' }
        ]
    },

    // §4.13 Note
    'note': {
        label: 'Note',
        description: 'Conveys informative text to provide further context and/or to provide additional analysis not contained in the STIX Objects.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gudodcg1sbb9',
        required: [
            { key: 'content', label: 'Content', type: 'text', description: 'The content of the note.', placeholder: 'Analysis notes...' }
        ],
        optional: [
            { key: 'abstract',     label: 'Abstract',      type: 'text', description: 'A brief summary of the note.' },
            { key: 'authors',      label: 'Authors',        type: 'list', description: 'The name(s) of the author(s).' },
            { key: 'object_refs',  label: 'Object Refs',    type: 'list', description: 'STIX Objects this note refers to.' }
        ]
    },

    // §4.14 Observed Data
    'observed-data': {
        label: 'Observed Data',
        description: 'Conveys information about cyber security related entities such as files, systems, and networks that have been observed.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_p49j1fwoxldc',
        required: [
            { key: 'first_observed',    label: 'First Observed',    type: 'timestamp', description: 'The beginning of the time window during which the data was seen.' },
            { key: 'last_observed',     label: 'Last Observed',     type: 'timestamp', description: 'The end of the time window.' },
            { key: 'number_observed',   label: 'Number Observed',   type: 'integer',   description: 'The number of times the objects were observed.', placeholder: '1' }
        ],
        optional: [
            { key: 'object_refs', label: 'Object Refs', type: 'list', description: 'A list of SCOs and SROs observed.' }
        ]
    },

    // §4.15 Opinion
    'opinion': {
        label: 'Opinion',
        description: 'An assessment of the correctness of the information in a STIX Object produced by a different entity.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ht1vtzfbtz1',
        required: [
            { key: 'opinion',  label: 'Opinion', type: 'enum', description: 'The opinion value.', vocabulary: 'opinion-enum' }
        ],
        optional: [
            { key: 'explanation',  label: 'Explanation',  type: 'text', description: 'Explanation of the opinion.' },
            { key: 'authors',      label: 'Authors',       type: 'list', description: 'Name(s) of the opinion author(s).' },
            { key: 'object_refs',  label: 'Object Refs',   type: 'list', description: 'STIX Objects that the opinion is being applied to.' }
        ]
    },

    // §4.16 Report
    'report': {
        label: 'Report',
        description: 'Collections of threat intelligence focused on one or more topics: threat actors, malware, attack techniques, etc.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_n8bjzg1ysgdq',
        required: [
            { key: 'name',      label: 'Name',       type: 'string',    description: 'A name for this report.', placeholder: 'e.g. APT29 Report' },
            { key: 'published', label: 'Published',   type: 'timestamp', description: 'Date this report was officially published.' }
        ],
        optional: [
            { key: 'description',   label: 'Description',    type: 'text',             description: 'A description / executive summary.' },
            { key: 'report_types',  label: 'Report Types',   type: 'list:open-vocab',  description: 'Primary subject(s) of the report.', vocabulary: 'report-type-ov' },
            { key: 'object_refs',   label: 'Object Refs',    type: 'list',             description: 'STIX Objects referenced in this report.' }
        ]
    },

    // §4.17 Threat Actor
    'threat-actor': {
        label: 'Threat Actor',
        description: 'Actual individuals, groups, or organizations believed to be operating with malicious intent.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_k017w16zutw',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'A name for this threat actor.', placeholder: 'e.g. Fancy Bear' }
        ],
        optional: [
            { key: 'description',             label: 'Description',             type: 'text',              description: 'More details and context.' },
            { key: 'threat_actor_types',      label: 'Threat Actor Types',      type: 'list:open-vocab',   description: 'Type(s) of this actor.', vocabulary: 'threat-actor-type-ov' },
            { key: 'aliases',                 label: 'Aliases',                 type: 'list',              description: 'Other names (e.g. APT28, Sofacy, Pawn Storm).' },
            { key: 'first_seen',              label: 'First Seen',              type: 'timestamp',         description: 'Earliest known activity.' },
            { key: 'last_seen',               label: 'Last Seen',               type: 'timestamp',         description: 'Most recent known activity.' },
            { key: 'roles',                   label: 'Roles',                   type: 'list:open-vocab',   description: 'Roles this actor plays.', vocabulary: 'threat-actor-role-ov' },
            { key: 'goals',                   label: 'Goals',                   type: 'list',              description: 'High-level goals.' },
            { key: 'sophistication',          label: 'Sophistication',          type: 'open-vocab',        description: 'Skill and resource level.', vocabulary: 'threat-actor-sophistication-ov' },
            { key: 'resource_level',          label: 'Resource Level',          type: 'open-vocab',        description: 'Organizational level at which this operates.', vocabulary: 'attack-resource-level-ov' },
            { key: 'primary_motivation',      label: 'Primary Motivation',      type: 'open-vocab',        description: 'Primary reason.', vocabulary: 'attack-motivation-ov' },
            { key: 'secondary_motivations',   label: 'Secondary Motivations',   type: 'list:open-vocab',   description: 'Additional motivations.', vocabulary: 'attack-motivation-ov' },
            { key: 'personal_motivations',    label: 'Personal Motivations',    type: 'list:open-vocab',   description: 'Personal reasons.', vocabulary: 'attack-motivation-ov' }
        ]
    },

    // §4.18 Tool
    'tool': {
        label: 'Tool',
        description: 'Legitimate software that can be used by threat actors to perform attacks (e.g. PsExec, Mimikatz).',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_z4voa9ndw8v',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'The name used to identify the tool.', placeholder: 'e.g. Mimikatz' }
        ],
        optional: [
            { key: 'description',       label: 'Description',    type: 'text',              description: 'Details about this tool.' },
            { key: 'tool_types',        label: 'Tool Types',     type: 'list:open-vocab',   description: 'Category of tools.', vocabulary: 'tool-type-ov' },
            { key: 'aliases',           label: 'Aliases',         type: 'list',              description: 'Alternative names.' },
            { key: 'kill_chain_phases', label: 'Kill Chain Phases', type: 'kill-chain-phases', description: 'Kill chain phase(s).' },
            { key: 'tool_version',      label: 'Tool Version',   type: 'string',            description: 'The version of the tool.' }
        ]
    },

    // §4.19 Vulnerability
    'vulnerability': {
        label: 'Vulnerability',
        description: 'A mistake in software that can be directly used by a hacker to gain access to a system or network.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_q5ytzmajn6re',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'A name used to identify the vulnerability.', placeholder: 'e.g. CVE-2021-44228 (Log4Shell)' }
        ],
        optional: [
            { key: 'description',          label: 'Description',          type: 'text',                description: 'A description providing more details.' },
            { key: 'external_references',  label: 'External References',  type: 'external-references', description: 'External references (e.g. CVE, NVD links).' }
        ]
    },

    // Custom / Extension type
    'x-custom': {
        label: 'Custom',
        description: 'A custom STIX extension object not defined in the core specification.',
        stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_8072zpptx2l4',
        required: [
            { key: 'name', label: 'Name', type: 'string', description: 'A name for this custom object.', placeholder: 'e.g. Custom Threat Intel' }
        ],
        optional: [
            { key: 'description',       label: 'Description',        type: 'text',  description: 'A description of this custom object.' },
            { key: 'customTypeName',    label: 'Custom Type Name',   type: 'string', description: 'A human-readable sub-type name (e.g. APT Group Profile).', placeholder: 'e.g. APT Group Profile' }
        ]
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// STIX Relationship types (SRO §5) — default relationship verbs by source SDO
// ─────────────────────────────────────────────────────────────────────────────
const STIX_RELATIONSHIP_DEFAULTS = {
    'attack-pattern':   'uses',
    'campaign':         'uses',
    'course-of-action': 'mitigates',
    'grouping':         'related-to',
    'identity':         'related-to',
    'indicator':        'indicates',
    'infrastructure':   'supports',
    'intrusion-set':    'uses',
    'location':         'related-to',
    'malware':          'uses',
    'malware-analysis': 'analysis-of',
    'note':             'related-to',
    'observed-data':    'related-to',
    'opinion':          'related-to',
    'report':           'related-to',
    'threat-actor':     'uses',
    'tool':             'uses',
    'vulnerability':    'related-to',
    'x-custom':         'related-to'
};

// ─────────────────────────────────────────────────────────────────────────────
// Helper: get all editable fields (required + optional) for a type
// ─────────────────────────────────────────────────────────────────────────────
function getStixFieldsForType(stixType) {
    const def = STIX_OBJECTS[stixType];
    if (!def) return { required: [], optional: [] };
    return {
        required: def.required || [],
        optional: def.optional || []
    };
}

// Helper: get all type keys
function getStixTypeKeys() {
    return Object.keys(STIX_OBJECTS);
}

// Helper: get label for a type
function getStixTypeLabel(stixType) {
    return STIX_OBJECTS[stixType]?.label || stixType;
}

// Helper: get vocabulary values for a field
function getStixVocabulary(vocabKey) {
    return STIX_VOCABULARIES[vocabKey] || [];
}

// Export for module usage (if needed)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { STIX_OBJECTS, STIX_COMMON_PROPERTIES, STIX_VOCABULARIES, STIX_RELATIONSHIP_DEFAULTS, getStixFieldsForType, getStixTypeKeys, getStixTypeLabel, getStixVocabulary };
}

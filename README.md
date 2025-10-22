# Custom Sigma Detection Rules

A collection of custom Sigma detection rules for identifying suspicious Windows activity patterns commonly associated with adversarial tactics, techniques, and procedures (TTPs).

## Overview

This repository contains 6 Sigma detection rules organized by MITRE ATT&CK tactics, focusing on credential access, process injection, and system reconnaissance activities.

## Rule Categories

### Credential Dumping
Rules detecting credential theft and memory scraping activities.

- **Credential Dumping via PowerShell ReadProcessMemory on LSASS** - Detects PowerShell accessing LSASS process memory for credential extraction.

### Execution
Rules detecting suspicious command execution and reconnaissance activities.

- **Suspicious Netsh Command Execution** - Detects malicious netsh usage including firewall manipulation, port forwarding, and helper DLL injection.
- **WMIC Query for Antivirus Information** - Detects reconnaissance queries targeting installed antivirus products via WMI.

### Privilege Escalation
Rules detecting process injection and privilege escalation techniques.

- **Anomalous Process Calling WriteProcessMemory** _(Elastic Security Specific)_ - Detects unusual processes calling WriteProcessMemory API, indicating potential process injection.
- **Mimikatz Process Injection Detection** _(Hybrid Rule)_ - Detects Mimikatz-style process injection techniques targeting sensitive processes.
- **Process Injection via QueueUserAPC** _(Elastic Security Specific)_ - Detects APC-based process injection techniques.

## Rule Types

### Standard Sigma Rules
These rules use standard Sigma field names and are compatible with common Sigma converters (sigmac, pySigma):
- Credential Dumping via PowerShell ReadProcessMemory on LSASS
- Suspicious Netsh Command Execution
- WMIC Query for Antivirus Information

### Elastic Security Specific Rules
These rules use Elastic Common Schema (ECS) fields and Elastic Endpoint event logs. They are **not compatible** with standard Sigma converters and require Elastic Security:
- Anomalous Process Calling WriteProcessMemory
- Process Injection via QueueUserAPC

### Hybrid Rules
These rules contain both standard Sigma detections and Elastic-specific detections:
- Mimikatz Process Injection Detection

## Usage

### Converting Standard Sigma Rules

Use [sigmac](https://github.com/SigmaHQ/sigma) or [pySigma](https://github.com/SigmaHQ/pySigma) to convert standard rules to your SIEM format:

```bash
# Convert to Splunk
sigmac -t splunk "Credential Dumping/Credential Dumping via PowerShell ReadProcessMemory on LSASS.yaml"

# Convert to QRadar
sigmac -t qradar "Execution/Suspicious Netsh Command Execution.yaml"

# Convert to Elasticsearch Query DSL
sigmac -t es-qs "Execution/wmic query for antivirus.yaml"
```

### Using Elastic Security Rules

For Elastic-specific rules, import directly into Kibana:

1. Navigate to Security → Rules → Detection rules (SIEM)
2. Click "Import" and select the YAML file
3. Adjust the rule settings as needed for your environment

## MITRE ATT&CK Coverage

| Tactic | Technique | Rule |
|--------|-----------|------|
| Credential Access | T1003.001 - LSASS Memory | Credential Dumping via PowerShell, Mimikatz Detection |
| Defense Evasion | T1055.002 - Portable Executable Injection | WriteProcessMemory Detection, Mimikatz Detection |
| Defense Evasion | T1055.004 - Asynchronous Procedure Call | QueueUserAPC Detection |
| Defense Evasion | T1562.004 - Disable/Modify Firewall | Suspicious Netsh Execution |
| Discovery | T1016 - System Network Config Discovery | Suspicious Netsh Execution |
| Discovery | T1518.001 - Security Software Discovery | WMIC Antivirus Query |
| Execution | T1059.001 - PowerShell | WMIC Antivirus Query, Credential Dumping |
| Command and Control | T1090.001 - Internal Proxy | Suspicious Netsh Execution |

## False Positives

All rules include documented false positive scenarios. Common sources include:
- Security and penetration testing tools (Mimikatz, PurpleSharp, etc.)
- System administration scripts and tools
- Debugging and development environments
- Legitimate security products performing memory scanning
- Software installers and updaters

**Recommendation:** Tune filters for your specific environment to reduce false positives.

## Rule Metadata

All rules include:
- **Unique ID** - UUID for rule tracking
- **MITRE ATT&CK Tags** - Mapped to relevant techniques
- **Risk Level** - Severity classification (medium/high)
- **Author** - Rule creator
- **Date** - Creation/modification date
- **References** - Links to threat intelligence and documentation
- **Status** - All rules marked as "experimental" and should be tested before production deployment

## Testing Recommendations

Before deploying to production:

1. **Test in a lab environment** with known-good and known-bad samples
2. **Review false positive rates** over 1-2 weeks in a monitoring-only mode
3. **Tune filters** based on your environment's legitimate processes
4. **Validate coverage** using tools like [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
5. **Document exceptions** for approved security tools and admin activities

## Contributing

When adding new rules:
- Use standard Sigma field names for portability
- Clearly mark Elastic-specific rules in the description
- Include MITRE ATT&CK mappings
- Document false positives
- Add references to threat intelligence
- Follow ISO 8601 date format (YYYY-MM-DD)
- Test rules before committing

## Repository Structure

```
custom_sigma_rules/
├── Credential Dumping/
│   └── Credential Dumping via PowerShell ReadProcessMemory on LSASS.yaml
├── Execution/
│   ├── Suspicious Netsh Command Execution.yaml
│   └── wmic query for antivirus.yaml
├── Privilege Escalation/
│   ├── Anomalous Process Calling WriteProcessMemory.yaml
│   ├── Mimikatz Process Injection Detection.yaml
│   └── Process Injection via QueueUserAPC.yaml
└── README.md
```

## Resources

- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [Sigma Rule Repository](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Elastic Security Detection Rules](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html)
- [Sigma Converter Tools](https://github.com/SigmaHQ/sigma/wiki/Tools)

## License

These rules are provided as-is for defensive security purposes only.

## Author

Sam Tanner / Samuel Tanner

## Status

All rules are currently marked as **experimental** and should undergo thorough testing and tuning before production deployment.

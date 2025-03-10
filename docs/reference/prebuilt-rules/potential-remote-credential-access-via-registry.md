---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-remote-credential-access-via-registry.html
---

# Potential Remote Credential Access via Registry [potential-remote-credential-access-via-registry]

Identifies remote access to the registry to potentially dump credential data from the Security Account Manager (SAM) registry hive in preparation for credential access and privileges elevation.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)
* [https://www.elastic.co/security-labs/detect-credential-access](https://www.elastic.co/security-labs/detect-credential-access)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Tactic: Credential Access
* Resources: Investigation Guide
* Data Source: Elastic Defend

**Version**: 111

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_756]

**Triage and analysis**

**Investigating Potential Remote Credential Access via Registry**

Dumping registry hives is a common way to access credential information. Some hives store credential material, such as the SAM hive, which stores locally cached credentials (SAM secrets), and the SECURITY hive, which stores domain cached credentials (LSA secrets). Dumping these hives in combination with the SYSTEM hive enables the attacker to decrypt these secrets.

Attackers can use tools like secretsdump.py or CrackMapExec to dump the registry hives remotely, and use dumped credentials to access other systems in the domain.

**Possible investigation steps**

* Identify the specifics of the involved assets, such as their role, criticality, and associated users.
* Identify the user account that performed the action and whether it should perform this kind of action.
* Determine the privileges of the compromised accounts.
* Investigate other alerts associated with the user/source host during the past 48 hours.
* Investigate potentially compromised accounts. Analysts can do this by searching for login events (e.g., 4624) to the target host.

**False positive analysis**

* This activity is unlikely to happen legitimately. Any activity that triggered the alert and is not inherently malicious must be monitored by the security team.

**Related rules**

* Credential Acquisition via Registry Hive Dumping - a7e7bfa3-088e-4f13-b29e-3986e0e756b8

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved hosts to prevent further post-compromise behavior.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Determine if other hosts were compromised.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Reimage the host operating system or restore the compromised files to clean versions.
* Ensure that the machine has the latest security updates and is not running unsupported Windows versions.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_486]

**Setup**

This rule uses Elastic Endpoint file creation and system integration events for correlation. Both data should be collected from the host for this detection to work.

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_804]

```js
file where host.os.type == "windows" and
  event.action == "creation" and process.name : "svchost.exe" and
  file.Ext.header_bytes : "72656766*" and user.id : ("S-1-5-21-*", "S-1-12-1-*") and file.size >= 30000 and
  file.path : ("?:\\Windows\\system32\\*.tmp", "?:\\WINDOWS\\Temp\\*.tmp")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: Security Account Manager
    * ID: T1003.002
    * Reference URL: [https://attack.mitre.org/techniques/T1003/002/](https://attack.mitre.org/techniques/T1003/002/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)




---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-sunburst-command-and-control-activity.html
---

# SUNBURST Command and Control Activity [prebuilt-rule-1-0-2-sunburst-command-and-control-activity]

The malware known as SUNBURST targets the SolarWind’s Orion business software for command and control. This rule detects post-exploitation command and control activity of the SUNBURST backdoor.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Command and Control

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1506]

## Triage and analysis

## Investigating SUNBURST Command and Control Activity

SUNBURST is a trojanized version of a digitally signed SolarWinds Orion plugin called
SolarWinds.Orion.Core.BusinessLayer.dll. The plugin contains a backdoor that communicates via HTTP to third-party
servers. After an initial dormant period of up to two weeks, SUNBURST may retrieve and execute commands that instruct
the backdoor to transfer files, execute files, profile the system, reboot the system, and disable system services.
The malware's network traffic attempts to blend in with legitimate SolarWinds activity by imitating the Orion
Improvement Program (OIP) protocol, and the malware stores persistent state data within legitimate plugin configuration files. The
backdoor uses multiple obfuscated blocklists to identify processes, services, and drivers associated with forensic and
anti-virus tools.

More details on SUNBURST can be found on the [Mandiant Report](https://www.mandiant.com/resources/sunburst-additional-technical-details).

This rule identifies suspicious network connections that attempt to blend in with legitimate SolarWinds activity
by imitating the Orion Improvement Program (OIP) protocol behavior.

### Possible investigation steps

- Investigate the process execution chain (parent process tree).
- Retrieve the executable involved:
  - Use a sandboxed malware analysis system to perform analysis.
    - Observe attempts to contact external domains and addresses.
  - Use the PowerShell Get-FileHash cmdlet to get the SHA-256 hash value of the file.
    - Search for the existence and reputation of this file in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
  - Manually analyze the executable to determine if malicious capabilities are present.
- Investigate whether the potential malware ran successfully, is active on the host, or was stopped by defenses.
- Investigate the network traffic.
- Investigate other alerts related to the user/host in the last 48 hours.
- Check for similar behavior in other hosts on the environment.

## False positive analysis

- False positives are unlikely for this rule.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement any temporary network rules, procedures, and segmentation required to contain the malware.
- Remove and block malicious artifacts identified on the triage.
- Reimage the host operating system and restore compromised files to clean versions.
- Upgrade SolarWinds systems to the latest version.

## Rule query [_rule_query_1741]

```js
network where event.type == "protocol" and network.protocol == "http" and
  process.name : ("ConfigurationWizard.exe",
                  "NetFlowService.exe",
                  "NetflowDatabaseMaintenance.exe",
                  "SolarWinds.Administration.exe",
                  "SolarWinds.BusinessLayerHost.exe",
                  "SolarWinds.BusinessLayerHostx64.exe",
                  "SolarWinds.Collector.Service.exe",
                  "SolarwindsDiagnostics.exe") and
  (http.request.body.content : "*/swip/Upload.ashx*" and http.request.body.content : ("POST*", "PUT*")) or
  (http.request.body.content : ("*/swip/SystemDescription*", "*/swip/Events*") and http.request.body.content : ("GET*", "HEAD*")) and
  not http.request.body.content : "*solarwinds.com*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Application Layer Protocol
    * ID: T1071
    * Reference URL: [https://attack.mitre.org/techniques/T1071/](https://attack.mitre.org/techniques/T1071/)

* Sub-technique:

    * Name: Web Protocols
    * ID: T1071.001
    * Reference URL: [https://attack.mitre.org/techniques/T1071/001/](https://attack.mitre.org/techniques/T1071/001/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Supply Chain Compromise
    * ID: T1195
    * Reference URL: [https://attack.mitre.org/techniques/T1195/](https://attack.mitre.org/techniques/T1195/)

* Sub-technique:

    * Name: Compromise Software Supply Chain
    * ID: T1195.002
    * Reference URL: [https://attack.mitre.org/techniques/T1195/002/](https://attack.mitre.org/techniques/T1195/002/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-network-tool-launched-inside-a-container.html
---

# Suspicious Network Tool Launched Inside A Container [suspicious-network-tool-launched-inside-a-container]

This rule detects commonly abused network utilities running inside a container. Network utilities like nc, nmap, dig, tcpdump, ngrep, telnet, mitmproxy, zmap can be used for malicious purposes such as network reconnaissance, monitoring, or exploitation, and should be monitored closely within a container.

**Rule type**: eql

**Rule indices**:

* logs-cloud_defend*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Data Source: Elastic Defend for Containers
* Domain: Container
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Tactic: Command and Control
* Tactic: Reconnaissance
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1012]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Network Tool Launched Inside A Container**

Containers are lightweight, portable units that encapsulate applications and their dependencies, often used to ensure consistent environments across development and production. Adversaries exploit network tools within containers for reconnaissance or lateral movement, leveraging utilities like `nc` or `nmap` to map networks or intercept traffic. The detection rule identifies these tools' execution by monitoring process starts and arguments, flagging potential misuse for further investigation.

**Possible investigation steps**

* Review the container ID and process name from the alert to identify which container and network tool triggered the alert.
* Examine the process arguments to understand the specific command or options used, which may provide insight into the intent of the tool’s execution.
* Check the container’s creation and modification timestamps to determine if the container was recently deployed or altered, which could indicate suspicious activity.
* Investigate the user or service account associated with the process start event to assess if it aligns with expected behavior or if it might be compromised.
* Analyze network logs and traffic patterns from the container to identify any unusual outbound connections or data exfiltration attempts.
* Correlate the alert with other security events or logs from the same container or host to identify potential lateral movement or further malicious activity.

**False positive analysis**

* Development and testing environments often use network tools for legitimate purposes such as debugging or network configuration. To manage this, create exceptions for containers identified as part of these environments by tagging them appropriately and excluding them from the rule.
* Automated scripts or orchestration tools may trigger network utilities for routine checks or maintenance tasks. Identify these scripts and whitelist their associated container IDs or process names to prevent false alerts.
* Some monitoring solutions deploy containers with built-in network tools for performance analysis. Verify the legitimacy of these containers and exclude them from the rule by using specific labels or container IDs.
* Containers used for educational or training purposes might intentionally run network tools. Ensure these containers are marked and excluded from detection by setting up rules based on their unique identifiers or labels.

**Response and remediation**

* Immediately isolate the affected container to prevent further network reconnaissance or lateral movement. This can be done by restricting its network access or stopping the container entirely.
* Conduct a thorough review of the container’s logs and process history to identify any unauthorized access or data exfiltration attempts. Focus on the execution of the flagged network utilities.
* Remove any unauthorized or suspicious network tools from the container to prevent further misuse. Ensure that only necessary and approved utilities are present.
* Patch and update the container image to address any vulnerabilities that may have been exploited. Rebuild and redeploy the container using the updated image.
* Implement network segmentation to limit the container’s access to sensitive resources and reduce the potential impact of similar threats in the future.
* Enhance monitoring and alerting for the execution of network utilities within containers, ensuring that any future occurrences are detected promptly.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems or containers have been compromised.


## Rule query [_rule_query_1062]

```js
process where container.id: "*" and event.type== "start" and
(
(process.name: ("nc", "ncat", "nmap", "dig", "nslookup", "tcpdump", "tshark", "ngrep", "telnet", "mitmproxy", "socat", "zmap", "masscan", "zgrab")) or
/*account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg*/
(process.args: ("nc", "ncat", "nmap", "dig", "nslookup", "tcpdump", "tshark", "ngrep", "telnet", "mitmproxy", "socat", "zmap", "masscan", "zgrab"))
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Network Service Discovery
    * ID: T1046
    * Reference URL: [https://attack.mitre.org/techniques/T1046/](https://attack.mitre.org/techniques/T1046/)

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Ingress Tool Transfer
    * ID: T1105
    * Reference URL: [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)

* Tactic:

    * Name: Reconnaissance
    * ID: TA0043
    * Reference URL: [https://attack.mitre.org/tactics/TA0043/](https://attack.mitre.org/tactics/TA0043/)

* Technique:

    * Name: Active Scanning
    * ID: T1595
    * Reference URL: [https://attack.mitre.org/techniques/T1595/](https://attack.mitre.org/techniques/T1595/)




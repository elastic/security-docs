---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-buffer-overflow-attack-detected.html
---

# Potential Buffer Overflow Attack Detected [prebuilt-rule-8-17-4-potential-buffer-overflow-attack-detected]

Detects potential buffer overflow attacks by querying the "Segfault Detected" pre-built rule signal index, through a threshold rule, with a minimum number of 100 segfault alerts in a short timespan. A large amount of segfaults in a short time interval could indicate application exploitation attempts.

**Rule type**: threshold

**Rule indices**:

* .alerts-security.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Tactic: Initial Access
* Use Case: Vulnerability
* Rule Type: Higher-Order Rule
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4529]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Buffer Overflow Attack Detected**

Buffer overflow attacks exploit vulnerabilities in software to execute arbitrary code, often leading to privilege escalation. Adversaries may trigger numerous segmentation faults (segfaults) on Linux systems as they attempt to exploit these vulnerabilities. The detection rule identifies potential attacks by monitoring for a surge in segfault alerts, indicating possible exploitation attempts, and correlates them with known threat tactics.

**Possible investigation steps**

* Review the alert details to confirm the presence of a surge in segfault alerts, focusing on the host.os.type:linux field to ensure the affected systems are Linux-based.
* Correlate the timestamps of the segfault alerts to identify any patterns or specific timeframes when the surge occurred, which might indicate the start of an exploitation attempt.
* Investigate the affected host(s) by examining system logs and application logs around the time of the segfault alerts to identify any suspicious activities or anomalies.
* Check for any recent changes or updates to the software running on the affected host(s) that might have introduced vulnerabilities.
* Look for any known vulnerabilities or exploits associated with the software or services running on the affected host(s) that could be targeted by a buffer overflow attack.
* Assess the network traffic to and from the affected host(s) during the time of the alerts to identify any unusual or unauthorized connections that could indicate an attack vector.
* Consult threat intelligence sources to determine if there are any ongoing campaigns or known threat actors targeting similar vulnerabilities or systems.

**False positive analysis**

* High-volume legitimate application crashes can trigger false positives, especially during software testing or development phases. Users should identify and exclude these applications from the rule by creating exceptions for specific processes known to cause frequent segfaults without malicious intent.
* System updates or patches may cause temporary spikes in segfault alerts as applications restart or reconfigure. Users can mitigate this by setting a temporary exception during scheduled maintenance windows.
* Custom scripts or automated tasks that interact with system memory in non-standard ways might generate segfaults. Review these scripts and, if verified as safe, exclude them from the rule to prevent false alerts.
* Certain security tools or monitoring software may intentionally cause segfaults as part of their operation. Identify these tools and add them to the exception list to avoid unnecessary alerts.
* Legacy applications with known stability issues might frequently cause segfaults. Consider updating or replacing these applications, or create exceptions if updates are not feasible.

**Response and remediation**

* Isolate the affected Linux host immediately to prevent further exploitation and lateral movement within the network.
* Terminate any suspicious processes identified on the affected host that are associated with the segfault alerts to halt potential malicious activity.
* Conduct a thorough analysis of the affected application or service to identify and patch the specific vulnerability being exploited, ensuring all software is updated to the latest secure versions.
* Review and enhance system and application logging to capture detailed information on segfault occurrences and related activities for future analysis and detection.
* Implement additional security controls such as application whitelisting and memory protection mechanisms (e.g., DEP, ASLR) to mitigate the risk of buffer overflow attacks.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Document the incident, including all actions taken and findings, to improve future response efforts and update incident response plans accordingly.


## Setup [_setup_1361]

**Setup**

This rule leverages alert data from other prebuilt detection rules to function correctly.

**Dependent Elastic Detection Rule Enablement**

As a higher-order rule (based on other detections), this rule also requires the following prerequisite Elastic detection rule to be installed and enabled: - Segfault Detected (5c81fc9d-1eae-437f-ba07-268472967013)


## Rule query [_rule_query_5521]

```js
kibana.alert.rule.rule_id:"5c81fc9d-1eae-437f-ba07-268472967013" and host.os.type:linux and event.kind:signal
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Exploit Public-Facing Application
    * ID: T1190
    * Reference URL: [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)




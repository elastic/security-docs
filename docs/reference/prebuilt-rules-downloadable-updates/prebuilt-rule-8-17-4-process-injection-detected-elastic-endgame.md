---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-process-injection-detected-elastic-endgame.html
---

# Process Injection - Detected - Elastic Endgame [prebuilt-rule-8-17-4-process-injection-detected-elastic-endgame]

Elastic Endgame detected Process Injection. Click the Elastic Endgame icon in the event.module column or the link in the rule.reference column for additional information.

**Rule type**: query

**Rule indices**:

* endgame-*

**Severity**: high

**Risk score**: 73

**Runs every**: 10m

**Searches indices from**: now-15m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 10000

**References**: None

**Tags**:

* Data Source: Elastic Endgame
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4677]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Process Injection - Detected - Elastic Endgame**

Elastic Endgame is a security solution that monitors and detects suspicious activities like process injection, a technique often used by adversaries to execute malicious code within the address space of another process, thereby evading detection. This detection rule identifies such threats by analyzing alerts and specific event actions related to kernel shellcode, indicating potential privilege escalation attempts. By leveraging MITRE ATT&CK frameworks, it effectively flags high-risk activities, aiding analysts in mitigating threats.

**Possible investigation steps**

* Review the alert details in the Elastic Endgame console by clicking the Elastic Endgame icon in the event.module column or the link in the rule.reference column to gather more context about the detected process injection.
* Examine the specific event.action and endgame.event_subtype_full fields to confirm the presence of kernel_shellcode_event, which indicates potential malicious activity.
* Analyze the process tree and parent-child relationships of the affected process to identify any unusual or unauthorized processes that may have initiated the injection.
* Check for any recent privilege escalation attempts or suspicious activities associated with the affected process by correlating with other alerts or logs in the system.
* Investigate the source and destination IP addresses, if available, to determine if there is any external communication that could suggest a command and control connection.
* Assess the risk and impact of the detected activity by considering the risk score and severity level, and prioritize response actions accordingly.
* If necessary, isolate the affected system to prevent further malicious activity and begin remediation efforts based on the findings.

**False positive analysis**

* Legitimate software updates or patches may trigger process injection alerts. Users can create exceptions for known update processes by identifying their unique process names or hashes.
* Security tools or monitoring software that use process injection for legitimate purposes might be flagged. Users should whitelist these tools by specifying their process identifiers or paths.
* Custom scripts or automation tasks that interact with system processes could be misidentified as threats. Users can exclude these scripts by defining their execution context or command-line arguments.
* Debugging or development activities involving process manipulation might cause false positives. Users should consider excluding these activities during known development periods or within specific environments.
* Virtualization or sandboxing solutions that mimic process injection techniques for isolation purposes may be detected. Users can create exceptions for these solutions by recognizing their specific signatures or behaviors.

**Response and remediation**

* Isolate the affected system immediately to prevent further spread of the malicious code. Disconnect it from the network and any shared resources.
* Terminate the malicious process identified by the alert to stop the execution of injected code. Use process management tools to safely end the process.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any additional threats or remnants of the attack.
* Review and analyze system logs and the specific event details from the alert to understand the scope of the intrusion and identify any other potentially compromised systems.
* Apply security patches and updates to the operating system and all software applications on the affected system to close any vulnerabilities exploited by the attacker.
* Restore the system from a known good backup taken before the incident occurred, ensuring that the backup is free from any malicious code.
* Report the incident to the appropriate internal security team or external authorities if required, providing them with detailed information about the attack and the steps taken for remediation.


## Setup [_setup_1492]

**Setup**

This rule is configured to generate more ***Max alerts per run*** than the default 1000 alerts per run set for all rules. This is to ensure that it captures as many alerts as possible.

***IMPORTANT:*** The rule’s ***Max alerts per run*** setting can be superseded by the `xpack.alerting.rules.run.alerts.max` Kibana config setting, which determines the maximum alerts generated by *any* rule in the Kibana alerting framework. For example, if `xpack.alerting.rules.run.alerts.max` is set to 1000, this rule will still generate no more than 1000 alerts even if its own ***Max alerts per run*** is set higher.

To make sure this rule can generate as many alerts as it’s configured in its own ***Max alerts per run*** setting, increase the `xpack.alerting.rules.run.alerts.max` system setting accordingly.

***NOTE:*** Changing `xpack.alerting.rules.run.alerts.max` is not possible in Serverless projects.


## Rule query [_rule_query_5632]

```js
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:kernel_shellcode_event or endgame.event_subtype_full:kernel_shellcode_event)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-agent-spoofing-mismatched-agent-id.html
---

# Agent Spoofing - Mismatched Agent ID [prebuilt-rule-8-17-4-agent-spoofing-mismatched-agent-id]

Detects events that have a mismatch on the expected event agent ID. The status "agent_id_mismatch/mismatch" occurs when the expected agent ID associated with the API key does not match the actual agent ID in an event. This could indicate attempts to spoof events in order to masquerade actual activity to evade detection.

**Rule type**: query

**Rule indices**:

* logs-*
* metrics-*
* traces-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Use Case: Threat Detection
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3955]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Agent Spoofing - Mismatched Agent ID**

In security environments, agent IDs uniquely identify software agents that report events. Adversaries may spoof these IDs to disguise unauthorized activities, evading detection systems. The detection rule identifies discrepancies between expected and actual agent IDs, flagging potential spoofing attempts. By monitoring for mismatches, it helps uncover efforts to masquerade malicious actions as legitimate.

**Possible investigation steps**

* Review the event logs to identify the specific events where the agent_id_status is marked as "agent_id_mismatch" or "mismatch" to understand the scope and frequency of the issue.
* Correlate the mismatched agent IDs with the associated API keys to determine if there are any patterns or commonalities that could indicate a targeted spoofing attempt.
* Investigate the source IP addresses and user accounts associated with the mismatched events to identify any unauthorized access or suspicious activity.
* Check for any recent changes or anomalies in the configuration or deployment of agents that could explain the mismatches, such as updates or reassignments.
* Analyze historical data to determine if similar mismatches have occurred in the past and whether they were resolved or linked to known issues or threats.
* Consult with the IT or security team to verify if there are any legitimate reasons for the agent ID discrepancies, such as testing or maintenance activities.

**False positive analysis**

* Legitimate software updates or patches may temporarily cause agent ID mismatches. Users should verify if the mismatches coincide with scheduled updates and consider excluding these events if confirmed.
* Network configuration changes, such as IP address reassignments, can lead to mismatches. Ensure that network changes are documented and correlate with the mismatched events before excluding them.
* Virtual machine snapshots or clones might result in duplicate agent IDs. Users should track virtual machine activities and exclude events from known snapshot or cloning operations.
* Load balancing or failover processes in high-availability environments can cause agent ID discrepancies. Review the infrastructure setup and exclude events that align with these processes.
* Testing environments often simulate various agent activities, leading to mismatches. Clearly separate test environments from production in monitoring systems and exclude test-related events.

**Response and remediation**

* Immediately isolate the affected systems to prevent further unauthorized access or data exfiltration. This can be done by disconnecting the system from the network or using network segmentation techniques.
* Conduct a thorough review of the logs and events associated with the mismatched agent ID to identify any unauthorized changes or activities. Focus on the specific events flagged by the detection rule.
* Revoke and reissue API keys associated with the compromised agent ID to prevent further misuse. Ensure that new keys are distributed securely and only to authorized personnel.
* Implement additional monitoring on the affected systems and related network segments to detect any further attempts at agent ID spoofing or other suspicious activities.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if the threat actor has compromised other parts of the network.
* Review and update access controls and authentication mechanisms to ensure that only legitimate agents can report events. Consider implementing multi-factor authentication for added security.
* Document the incident, including all actions taken, and conduct a post-incident review to identify any gaps in detection or response. Use this information to enhance future threat detection and response capabilities.


## Rule query [_rule_query_4972]

```js
event.agent_id_status:(agent_id_mismatch or mismatch)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)




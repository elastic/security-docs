---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-memory-grep-activity.html
---

# Suspicious Memory grep Activity [prebuilt-rule-8-17-4-suspicious-memory-grep-activity]

Monitors for grep activity related to memory mapping. The /proc/*/maps file in Linux provides a memory map for a specific process, detailing the memory segments, permissions, and what files are mapped to these segments. Attackers may read a process’s memory map to identify memory addresses for code injection or process hijacking.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4381]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Memory grep Activity**

In Linux, the `/proc/*/maps` file reveals a process’s memory layout, crucial for debugging but exploitable by attackers for malicious activities like code injection. Adversaries may use tools like `grep` to scan these memory maps for specific segments, aiding in process manipulation. The detection rule identifies such suspicious `grep` usage by monitoring process initiation events, focusing on arguments that indicate potential memory mapping exploration.

**Possible investigation steps**

* Review the process initiation event details to confirm the presence of grep or its variants (egrep, fgrep, rgrep) in the process name field.
* Examine the process arguments to verify if they include memory segments like [stack], [vdso], or [heap], which could indicate an attempt to explore memory mappings.
* Identify the user or service account associated with the suspicious process to determine if the activity aligns with expected behavior or if it might be unauthorized.
* Check the parent process of the suspicious grep activity to understand the context in which it was executed and assess if it was initiated by a legitimate application or script.
* Investigate any recent changes or anomalies in the system logs around the time of the alert to identify potential indicators of compromise or related suspicious activities.
* Correlate this event with other security alerts or logs from the same host to identify patterns or a broader attack campaign.

**False positive analysis**

* System administrators or developers may use grep to inspect memory maps for legitimate debugging or performance tuning. To handle this, create exceptions for known user accounts or specific scripts that perform these tasks regularly.
* Automated monitoring tools might use grep to check memory usage patterns as part of routine health checks. Identify these tools and exclude their process IDs or command patterns from triggering alerts.
* Security software or intrusion detection systems could use grep to scan memory maps as part of their normal operations. Verify these processes and whitelist them to prevent unnecessary alerts.
* Developers running test scripts that include memory map analysis might trigger this rule. Document these scripts and add them to an exception list to avoid false positives.
* Some legitimate applications may use grep to read memory maps for configuration or optimization purposes. Monitor these applications and adjust the rule to exclude their specific command-line arguments.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement or further exploitation.
* Terminate any suspicious processes identified by the detection rule, specifically those involving `grep` or its variants accessing memory maps.
* Conduct a memory dump and forensic analysis of the affected system to identify any injected code or unauthorized modifications.
* Review and audit access logs to determine if there was unauthorized access to the `/proc/*/maps` files and identify any potential data exfiltration.
* Apply patches and updates to the operating system and applications to mitigate known vulnerabilities that could be exploited for similar attacks.
* Implement stricter access controls and monitoring on sensitive files and directories, such as `/proc/*/maps`, to prevent unauthorized access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the need for broader organizational response measures.


## Rule query [_rule_query_5373]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  process.name in ("grep", "egrep", "fgrep", "rgrep") and process.args in ("[stack]", "[vdso]", "[heap]")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Process Discovery
    * ID: T1057
    * Reference URL: [https://attack.mitre.org/techniques/T1057/](https://attack.mitre.org/techniques/T1057/)




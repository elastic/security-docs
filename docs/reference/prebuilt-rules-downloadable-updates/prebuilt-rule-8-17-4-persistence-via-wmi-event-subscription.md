---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-persistence-via-wmi-event-subscription.html
---

# Persistence via WMI Event Subscription [prebuilt-rule-8-17-4-persistence-via-wmi-event-subscription]

An adversary can use Windows Management Instrumentation (WMI) to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* winlogbeat-*
* logs-windows.forwarded*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*
* logs-crowdstrike.fdr*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-1](https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-1)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 314

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4949]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Persistence via WMI Event Subscription**

Windows Management Instrumentation (WMI) is a powerful framework for managing data and operations on Windows systems. Adversaries exploit WMI by creating event subscriptions that trigger malicious code execution, ensuring persistence. The detection rule identifies suspicious use of `wmic.exe` to create event consumers, signaling potential abuse of WMI for persistence by monitoring specific process activities and arguments.

**Possible investigation steps**

* Review the process execution details for `wmic.exe` to confirm the presence of suspicious arguments such as "create", "ActiveScriptEventConsumer", or "CommandLineEventConsumer" that indicate potential WMI event subscription abuse.
* Examine the parent process of `wmic.exe` to determine how it was launched and assess whether this aligns with expected behavior or if it suggests malicious activity.
* Investigate the user account associated with the `wmic.exe` process to determine if it has the necessary privileges to create WMI event subscriptions and whether the account activity is consistent with normal operations.
* Check for any recent changes or additions to WMI event filters, consumers, or bindings on the affected system to identify unauthorized modifications that could indicate persistence mechanisms.
* Correlate the alert with other security events or logs from data sources like Microsoft Defender for Endpoint or Sysmon to gather additional context and identify any related suspicious activities or patterns.

**False positive analysis**

* Legitimate administrative tasks using wmic.exe may trigger the rule, such as system monitoring or configuration changes. To handle this, identify and document routine administrative scripts and exclude them from triggering alerts.
* Software installations or updates that use WMI for legitimate event subscriptions can be mistaken for malicious activity. Maintain a list of trusted software and their expected behaviors to create exceptions in the detection rule.
* Automated system management tools that rely on WMI for event handling might cause false positives. Review and whitelist these tools by verifying their source and purpose to prevent unnecessary alerts.
* Security software or monitoring solutions that utilize WMI for legitimate purposes can be flagged. Collaborate with IT and security teams to identify these tools and adjust the rule to exclude their known benign activities.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes related to `wmic.exe` that are identified as creating event consumers, specifically those involving "ActiveScriptEventConsumer" or "CommandLineEventConsumer".
* Remove any unauthorized WMI event subscriptions by using tools like `wevtutil` or PowerShell scripts to list and delete suspicious event filters, consumers, and bindings.
* Conduct a thorough review of the system’s WMI repository to ensure no other malicious or unauthorized configurations exist.
* Restore the system from a known good backup if the integrity of the system is compromised and cannot be assured through manual remediation.
* Update and patch the system to the latest security standards to mitigate any vulnerabilities that may have been exploited.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.


## Rule query [_rule_query_5904]

```js
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "wmic.exe" or ?process.pe.original_file_name == "wmic.exe") and
  process.args : "create" and
  process.args : ("ActiveScriptEventConsumer", "CommandLineEventConsumer")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Windows Management Instrumentation Event Subscription
    * ID: T1546.003
    * Reference URL: [https://attack.mitre.org/techniques/T1546/003/](https://attack.mitre.org/techniques/T1546/003/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Windows Management Instrumentation
    * ID: T1047
    * Reference URL: [https://attack.mitre.org/techniques/T1047/](https://attack.mitre.org/techniques/T1047/)




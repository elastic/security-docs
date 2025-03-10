---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-wmi-event-subscription-created.html
---

# Suspicious WMI Event Subscription Created [prebuilt-rule-8-17-4-suspicious-wmi-event-subscription-created]

Detects the creation of a WMI Event Subscription. Attackers can abuse this mechanism for persistence or to elevate to SYSTEM privileges.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.sysmon_operational-*
* logs-endpoint.events.api-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
* [https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96](https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Sysmon
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 307

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4939]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious WMI Event Subscription Created**

Windows Management Instrumentation (WMI) is a powerful framework for managing data and operations on Windows systems. It allows for event subscriptions that can trigger actions based on system events. Adversaries exploit this for persistence by creating event subscriptions that execute malicious scripts or commands. The detection rule identifies such abuse by monitoring specific event codes and API calls related to the creation of suspicious WMI event consumers, flagging potential threats.

**Possible investigation steps**

* Review the event logs for event code 21 in the windows.sysmon_operational dataset to identify the specific WMI event subscription created, focusing on the winlog.event_data.Operation and winlog.event_data.Consumer fields.
* Examine the process details associated with the IWbemServices::PutInstance API call in the endpoint.events.api dataset, particularly the process.Ext.api.parameters.consumer_type, to determine the nature of the consumer created.
* Investigate the source and context of the command or script associated with the CommandLineEventConsumer or ActiveScriptEventConsumer to assess its legitimacy and potential malicious intent.
* Check for any related processes or activities around the time of the event to identify potential lateral movement or further persistence mechanisms.
* Correlate the findings with other security alerts or logs to determine if this event is part of a broader attack pattern or campaign.

**False positive analysis**

* Legitimate administrative scripts or tools may create WMI event subscriptions for system monitoring or automation. Review the source and context of the event to determine if it aligns with known administrative activities.
* Software installations or updates might use WMI event subscriptions as part of their setup or configuration processes. Verify if the event coincides with recent software changes and consider excluding these specific events if they are routine.
* Security software or management tools often use WMI for legitimate purposes. Identify and document these tools in your environment, and create exceptions for their known behaviors to reduce noise.
* Scheduled tasks or system maintenance scripts may trigger similar events. Cross-reference with scheduled task logs or maintenance windows to confirm if these are expected activities.
* Custom scripts developed in-house for system management might inadvertently match the detection criteria. Ensure these scripts are documented and consider excluding their specific signatures from the rule.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes associated with the WMI event subscription, specifically those linked to CommandLineEventConsumer or ActiveScriptEventConsumer.
* Remove the malicious WMI event subscription by using WMI management tools or scripts to delete the identified event consumer.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any additional threats.
* Review and reset any compromised credentials, especially if SYSTEM privileges were potentially accessed or escalated.
* Monitor the network for any signs of similar activity or attempts to recreate the WMI event subscription, using enhanced logging and alerting mechanisms.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the potential impact on other systems within the network.


## Rule query [_rule_query_5894]

```js
any where
 (
   (event.dataset == "windows.sysmon_operational" and event.code == "21" and
    winlog.event_data.Operation : "Created" and winlog.event_data.Consumer : ("*subscription:CommandLineEventConsumer*", "*subscription:ActiveScriptEventConsumer*")) or

   (event.dataset == "endpoint.events.api" and event.provider == "Microsoft-Windows-WMI-Activity" and process.Ext.api.name == "IWbemServices::PutInstance" and
    process.Ext.api.parameters.consumer_type in ("ActiveScriptEventConsumer", "CommandLineEventConsumer"))
 )
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




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/azure-diagnostic-settings-deletion.html
---

# Azure Diagnostic Settings Deletion [azure-diagnostic-settings-deletion]

Identifies the deletion of diagnostic settings in Azure, which send platform logs and metrics to different destinations. An adversary may delete diagnostic settings in an attempt to evade defenses.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-settings](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-settings)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_186]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Diagnostic Settings Deletion**

Azure Diagnostic Settings are crucial for monitoring and logging platform activities, sending data to various destinations for analysis. Adversaries may delete these settings to hinder detection and analysis of their activities, effectively evading defenses. The detection rule identifies such deletions by monitoring specific Azure activity logs for successful deletion operations, flagging potential defense evasion attempts.

**Possible investigation steps**

* Review the Azure activity logs to confirm the deletion event by filtering for the operation name "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE" and ensuring the event outcome is marked as Success.
* Identify the user or service principal responsible for the deletion by examining the associated user identity or service principal ID in the activity logs.
* Check the timestamp of the deletion event to determine when the diagnostic settings were removed and correlate this with other security events or alerts around the same time.
* Investigate the affected resources by identifying which diagnostic settings were deleted and assess the potential impact on monitoring and logging capabilities.
* Review any recent changes or activities performed by the identified user or service principal to determine if there are other suspicious actions that might indicate malicious intent.
* Assess the current security posture by ensuring that diagnostic settings are reconfigured and that logging and monitoring are restored to maintain visibility into platform activities.

**False positive analysis**

* Routine maintenance activities by authorized personnel may trigger the rule. Ensure that maintenance schedules are documented and align with the detected events.
* Automated scripts or tools used for managing Azure resources might delete diagnostic settings as part of their operation. Review and whitelist these scripts if they are verified as non-threatening.
* Changes in organizational policy or compliance requirements could lead to legitimate deletions. Confirm with relevant teams if such policy changes are in effect.
* Test environments often undergo frequent configuration changes, including the deletion of diagnostic settings. Consider excluding these environments from the rule or adjusting the rule to account for their unique behavior.
* Ensure that any third-party integrations or services with access to Azure resources are reviewed, as they might inadvertently delete diagnostic settings during their operations.

**Response and remediation**

* Immediately isolate affected Azure resources to prevent further unauthorized changes or deletions. This may involve temporarily restricting access to the affected subscriptions or resource groups.
* Review the Azure activity logs to identify the source of the deletion request, including the user account and IP address involved. This will help determine if the action was authorized or malicious.
* Recreate the deleted diagnostic settings as soon as possible to restore logging and monitoring capabilities. Ensure that logs are being sent to secure and appropriate destinations.
* Conduct a thorough investigation of the user account involved in the deletion. If the account is compromised, reset credentials, and review permissions to ensure they are appropriate and follow the principle of least privilege.
* Escalate the incident to the security operations team for further analysis and to determine if additional resources or expertise are needed to address the threat.
* Implement additional monitoring and alerting for similar deletion activities to ensure rapid detection and response to future attempts.
* Review and update access controls and policies related to diagnostic settings to prevent unauthorized deletions, ensuring that only trusted and necessary personnel have the ability to modify these settings.


## Setup [_setup_123]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_191]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE" and event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)




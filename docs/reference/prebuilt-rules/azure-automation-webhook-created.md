---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/azure-automation-webhook-created.html
---

# Azure Automation Webhook Created [azure-automation-webhook-created]

Identifies when an Azure Automation webhook is created. Azure Automation runbooks can be configured to execute via a webhook. A webhook uses a custom URL passed to Azure Automation along with a data payload specific to the runbook. An adversary may create a webhook in order to trigger a runbook that contains malicious code.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor](https://powerzure.readthedocs.io/en/latest/Functions/operational.md#create-backdoor)
* [https://github.com/hausec/PowerZure](https://github.com/hausec/PowerZure)
* [https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a](https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a)
* [https://www.ciraltos.com/webhooks-and-azure-automation-runbooks/](https://www.ciraltos.com/webhooks-and-azure-automation-runbooks/)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Configuration Audit
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_181]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Automation Webhook Created**

Azure Automation webhooks enable automated task execution via HTTP requests, integrating with external systems. Adversaries may exploit this by creating webhooks to trigger runbooks with harmful scripts, maintaining persistence. The detection rule identifies webhook creation events, focusing on specific operation names and successful outcomes, to flag potential misuse in cloud environments.

**Possible investigation steps**

* Review the Azure activity logs to identify the user or service principal that initiated the webhook creation by examining the `event.dataset` and `azure.activitylogs.operation_name` fields.
* Check the associated runbook linked to the created webhook to determine its purpose and inspect its content for any potentially malicious scripts or commands.
* Investigate the source IP address and location from which the webhook creation request originated to identify any unusual or unauthorized access patterns.
* Verify the legitimacy of the webhook by contacting the owner of the Azure Automation account or the relevant team to confirm if the webhook creation was expected and authorized.
* Assess the broader context of the activity by reviewing recent changes or activities in the Azure Automation account to identify any other suspicious actions or configurations.

**False positive analysis**

* Routine webhook creations for legitimate automation tasks can trigger false positives. Review the context of the webhook creation, such as the associated runbook and its purpose, to determine if it aligns with expected operations.
* Frequent webhook creations by trusted users or service accounts may not indicate malicious activity. Consider creating exceptions for these users or accounts to reduce noise in alerts.
* Automated deployment processes that involve creating webhooks as part of their workflow can be mistaken for suspicious activity. Document these processes and exclude them from triggering alerts if they are verified as safe.
* Integration with third-party services that require webhook creation might generate alerts. Verify these integrations and whitelist them if they are part of approved business operations.
* Regularly review and update the list of exceptions to ensure that only verified non-threatening behaviors are excluded, maintaining the effectiveness of the detection rule.

**Response and remediation**

* Immediately disable the suspicious webhook to prevent further execution of potentially harmful runbooks.
* Review the runbook associated with the webhook for any unauthorized or malicious scripts and remove or quarantine any identified threats.
* Conduct a thorough audit of recent changes in the Azure Automation account to identify any unauthorized access or modifications.
* Revoke any compromised credentials and enforce multi-factor authentication (MFA) for all accounts with access to Azure Automation.
* Notify the security team and relevant stakeholders about the incident for further investigation and to ensure awareness of potential threats.
* Implement enhanced monitoring and alerting for webhook creation and execution activities to detect similar threats in the future.
* Document the incident, including actions taken and lessons learned, to improve response strategies and prevent recurrence.


## Setup [_setup_118]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_186]

```js
event.dataset:azure.activitylogs and
  azure.activitylogs.operation_name:
    (
      "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/ACTION" or
      "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/WRITE"
    ) and
  event.outcome:(Success or success)
```



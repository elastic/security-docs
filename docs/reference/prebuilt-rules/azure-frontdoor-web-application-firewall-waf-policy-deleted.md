---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/azure-frontdoor-web-application-firewall-waf-policy-deleted.html
---

# Azure Frontdoor Web Application Firewall (WAF) Policy Deleted [azure-frontdoor-web-application-firewall-waf-policy-deleted]

Identifies the deletion of a Frontdoor Web Application Firewall (WAF) Policy in Azure. An adversary may delete a Frontdoor Web Application Firewall (WAF) Policy in an attempt to evade defenses and/or to eliminate barriers to their objective.

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

* [https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#networking](https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#networking)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Network Security Monitoring
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_194]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Frontdoor Web Application Firewall (WAF) Policy Deleted**

Azure Frontdoor WAF policies are crucial for protecting web applications by filtering and monitoring HTTP requests to block malicious traffic. Adversaries may delete these policies to bypass security measures, facilitating unauthorized access or data exfiltration. The detection rule identifies such deletions by monitoring Azure activity logs for specific delete operations, signaling potential defense evasion attempts.

**Possible investigation steps**

* Review the Azure activity logs to confirm the deletion event by filtering for the operation name "MICROSOFT.NETWORK/FRONTDOORWEBAPPLICATIONFIREWALLPOLICIES/DELETE" and ensure the event outcome is marked as Success.
* Identify the user or service principal responsible for the deletion by examining the associated user identity information in the activity logs.
* Check the timestamp of the deletion event to determine if it coincides with any other suspicious activities or alerts in the environment.
* Investigate the context of the deletion by reviewing any recent changes or incidents involving the affected Azure Frontdoor instance or related resources.
* Assess the impact of the deletion by identifying which web applications were protected by the deleted WAF policy and evaluating their current exposure to threats.
* Review access logs and network traffic for the affected web applications to detect any unusual or unauthorized access attempts following the policy deletion.

**False positive analysis**

* Routine maintenance or updates by authorized personnel may lead to the deletion of WAF policies. To manage this, create exceptions for known maintenance windows or specific user accounts responsible for these tasks.
* Automated scripts or tools used for infrastructure management might delete and recreate WAF policies as part of their normal operation. Identify these scripts and exclude their activity from triggering alerts.
* Changes in organizational policy or architecture could necessitate the removal of certain WAF policies. Document these changes and adjust the detection rule to account for them by excluding specific policy names or identifiers.
* Test environments may frequently add and remove WAF policies as part of development cycles. Consider excluding activity from test environments by filtering based on resource group names or tags associated with non-production environments.

**Response and remediation**

* Immediately isolate the affected Azure Frontdoor instance to prevent further unauthorized access or data exfiltration.
* Review Azure activity logs to identify the user or service principal responsible for the deletion and assess their access permissions.
* Recreate the deleted WAF policy using the latest backup or configuration template to restore security controls.
* Implement conditional access policies to restrict access to Azure management operations, ensuring only authorized personnel can modify WAF policies.
* Notify the security operations team and relevant stakeholders about the incident for further investigation and monitoring.
* Conduct a post-incident review to identify gaps in security controls and update incident response plans accordingly.
* Enhance monitoring by setting up alerts for any future deletions of critical security policies to ensure rapid detection and response.


## Setup [_setup_129]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_199]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/FRONTDOORWEBAPPLICATIONFIREWALLPOLICIES/DELETE" and event.outcome:(Success or success)
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




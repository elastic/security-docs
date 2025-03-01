---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/azure-application-credential-modification.html
---

# Azure Application Credential Modification [azure-application-credential-modification]

Identifies when a new credential is added to an application in Azure. An application may use a certificate or secret string to prove its identity when requesting a token. Multiple certificates and secrets can be added for an application and an adversary may abuse this by creating an additional authentication method to evade defenses or persist in an environment.

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

* [https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Identity and Access Audit
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_177]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Application Credential Modification**

Azure applications use credentials like certificates or secret strings for identity verification during token requests. Adversaries may exploit this by adding unauthorized credentials, enabling persistent access or evading defenses. The detection rule monitors audit logs for successful updates to application credentials, flagging potential misuse by identifying unauthorized credential modifications.

**Possible investigation steps**

* Review the Azure audit logs to identify the specific application that had its credentials updated, focusing on entries with the operation name "Update application - Certificates and secrets management" and a successful outcome.
* Determine the identity of the user or service principal that performed the credential modification by examining the associated user or principal ID in the audit log entry.
* Investigate the context of the credential modification by checking for any recent changes or unusual activities related to the application, such as modifications to permissions or roles.
* Assess the legitimacy of the new credential by verifying if it aligns with expected operational procedures or if it was authorized by a known and trusted entity.
* Check for any additional suspicious activities in the audit logs around the same timeframe, such as failed login attempts or other modifications to the application, to identify potential indicators of compromise.
* Contact the application owner or relevant stakeholders to confirm whether the credential addition was expected and authorized, and gather any additional context or concerns they might have.

**False positive analysis**

* Routine credential updates by authorized personnel can trigger alerts. Regularly review and document credential management activities to distinguish between legitimate and suspicious actions.
* Automated processes or scripts that update application credentials as part of maintenance or deployment cycles may cause false positives. Identify and whitelist these processes to prevent unnecessary alerts.
* Credential updates during application scaling or migration might be flagged. Coordinate with IT teams to schedule these activities and temporarily adjust monitoring thresholds or exclusions.
* Third-party integrations that require periodic credential updates can be mistaken for unauthorized changes. Maintain an inventory of such integrations and establish baseline behaviors to filter out benign activities.
* Frequent updates by specific service accounts could be part of normal operations. Monitor these accounts separately and consider creating exceptions for known, non-threatening patterns.

**Response and remediation**

* Immediately revoke the unauthorized credentials by accessing the Azure portal and removing any suspicious certificates or secret strings associated with the affected application.
* Conduct a thorough review of the application’s access logs to identify any unauthorized access or actions performed using the compromised credentials.
* Reset and update all legitimate credentials for the affected application to ensure no further unauthorized access can occur.
* Notify the security team and relevant stakeholders about the incident, providing details of the unauthorized credential modification and any potential impact.
* Implement additional monitoring on the affected application to detect any further unauthorized changes or access attempts.
* Review and tighten access controls and permissions for managing application credentials to prevent unauthorized modifications in the future.
* If necessary, escalate the incident to higher-level security management or external cybersecurity experts for further investigation and response.


## Setup [_setup_114]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_182]

```js
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Update application - Certificates and secrets management" and event.outcome:(success or Success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Use Alternate Authentication Material
    * ID: T1550
    * Reference URL: [https://attack.mitre.org/techniques/T1550/](https://attack.mitre.org/techniques/T1550/)

* Sub-technique:

    * Name: Application Access Token
    * ID: T1550.001
    * Reference URL: [https://attack.mitre.org/techniques/T1550/001/](https://attack.mitre.org/techniques/T1550/001/)




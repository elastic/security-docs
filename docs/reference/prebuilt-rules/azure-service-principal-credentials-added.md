---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/azure-service-principal-credentials-added.html
---

# Azure Service Principal Credentials Added [azure-service-principal-credentials-added]

Identifies when new Service Principal credentials have been added in Azure. In most organizations, credentials will be added to service principals infrequently. Hijacking an application (by adding a rogue secret or certificate) with granted permissions will allow the attacker to access data that is normally protected by MFA requirements.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.fireeye.com/content/dam/collateral/en/wp-m-unc2452.pdf](https://www.fireeye.com/content/dam/collateral/en/wp-m-unc2452.pdf)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Identity and Access Audit
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_205]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Service Principal Credentials Added**

Azure Service Principals are identities used by applications or services to access Azure resources securely. They are typically granted specific permissions, and credentials are rarely updated. Adversaries may exploit this by adding unauthorized credentials, gaining access to sensitive data without triggering MFA. The detection rule monitors audit logs for successful additions of service principal credentials, flagging potential unauthorized access attempts.

**Possible investigation steps**

* Review the Azure audit logs to identify the specific service principal for which credentials were added, focusing on entries with the operation name "Add service principal credentials" and a successful outcome.
* Determine the identity of the user or application that performed the credential addition by examining the associated user or application ID in the audit log entry.
* Investigate the permissions and roles assigned to the affected service principal to assess the potential impact of unauthorized access.
* Check for any recent changes or unusual activity associated with the service principal, such as modifications to permissions or unexpected resource access patterns.
* Correlate the event with other security logs and alerts to identify any related suspicious activities or potential indicators of compromise within the environment.
* Contact the owner or responsible team for the service principal to verify if the credential addition was authorized and legitimate.

**False positive analysis**

* Routine credential updates for service principals used in automated deployment processes can trigger alerts. To manage this, identify and document these processes, then create exceptions for known service principals involved in regular updates.
* Credential additions by authorized IT personnel during scheduled maintenance or upgrades may be flagged. Implement a change management process to log and verify these activities, allowing you to exclude them from triggering alerts.
* Integration of new third-party applications that require service principal credentials might cause false positives. Maintain an inventory of approved third-party integrations and exclude their credential additions from monitoring.
* Development and testing environments often see frequent credential changes. Segregate these environments from production in your monitoring setup to reduce unnecessary alerts.
* Credential rotations as part of security best practices can be mistaken for unauthorized additions. Establish a schedule for credential rotations and configure your monitoring to recognize these as legitimate activities.

**Response and remediation**

* Immediately revoke the newly added credentials for the affected Azure Service Principal to prevent unauthorized access.
* Conduct a thorough review of the audit logs to identify any unauthorized activities performed using the compromised Service Principal credentials.
* Reset and update the credentials for the affected Service Principal, ensuring they are stored securely and access is restricted to authorized personnel only.
* Notify the security team and relevant stakeholders about the incident, providing details of the unauthorized credential addition and any potential data access.
* Implement additional monitoring on the affected Service Principal and related resources to detect any further suspicious activities.
* Review and tighten the permissions granted to the Service Principal to ensure they follow the principle of least privilege.
* Consider enabling conditional access policies or additional security measures, such as IP whitelisting, to enhance protection against similar threats in the future.


## Setup [_setup_140]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_210]

```js
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add service principal credentials" and event.outcome:(success or Success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Resource Hijacking
    * ID: T1496
    * Reference URL: [https://attack.mitre.org/techniques/T1496/](https://attack.mitre.org/techniques/T1496/)




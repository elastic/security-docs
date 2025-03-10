---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-azure-key-vault-modified.html
---

# Azure Key Vault Modified [prebuilt-rule-8-17-4-azure-key-vault-modified]

Identifies modifications to a Key Vault in Azure. The Key Vault is a service that safeguards encryption keys and secrets like certificates, connection strings, and passwords. Because this data is sensitive and business critical, access to key vaults should be secured to allow only authorized applications and users.

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

* [https://docs.microsoft.com/en-us/azure/key-vault/general/basic-concepts](https://docs.microsoft.com/en-us/azure/key-vault/general/basic-concepts)
* [https://docs.microsoft.com/en-us/azure/key-vault/general/secure-your-key-vault](https://docs.microsoft.com/en-us/azure/key-vault/general/secure-your-key-vault)
* [https://www.elastic.co/security-labs/detect-credential-access](https://www.elastic.co/security-labs/detect-credential-access)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4087]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Key Vault Modified**

Azure Key Vault is a critical service for managing sensitive information like encryption keys and secrets. It ensures that only authorized users and applications can access these resources. However, adversaries may attempt to modify Key Vault settings to gain unauthorized access to credentials. The detection rule monitors for successful write operations to Key Vaults, flagging potential unauthorized modifications that could indicate credential access attempts.

**Possible investigation steps**

* Review the Azure activity logs to identify the specific user or application that performed the write operation on the Key Vault by examining the user identity and application ID fields.
* Check the timestamp of the write operation to determine if it aligns with expected maintenance windows or known changes, which could indicate legitimate activity.
* Investigate the specific changes made to the Key Vault by reviewing the operation details to understand what was modified, such as access policies or secret values.
* Correlate the activity with other security logs or alerts to identify any related suspicious behavior, such as failed login attempts or unusual access patterns from the same user or application.
* Verify if the user or application that performed the write operation had legitimate access and permissions to modify the Key Vault by reviewing their role assignments and access policies.
* Assess the potential impact of the modification by determining if any sensitive keys or secrets were exposed or altered, and evaluate the risk to the organization.

**False positive analysis**

* Routine administrative updates to Key Vault configurations by authorized personnel can trigger alerts. To manage this, maintain a list of known administrative accounts and exclude their activities from triggering alerts.
* Automated scripts or applications that regularly update Key Vault settings as part of normal operations may cause false positives. Identify these scripts and whitelist their operations to prevent unnecessary alerts.
* Scheduled maintenance activities that involve updating Key Vault settings can be mistaken for unauthorized modifications. Document these activities and create exceptions for the time frames during which they occur.
* Integration with third-party services that require periodic updates to Key Vault settings might generate alerts. Verify these integrations and exclude their operations if they are deemed secure and necessary.

**Response and remediation**

* Immediately revoke access to the affected Key Vault for any unauthorized users or applications identified during the investigation to prevent further unauthorized access.
* Rotate all secrets, keys, and certificates stored in the compromised Key Vault to ensure that any potentially exposed credentials are no longer valid.
* Conduct a thorough review of the Key Vault’s access policies and permissions to ensure that only authorized users and applications have the necessary access, and implement stricter access controls if needed.
* Enable logging and monitoring for the Key Vault to capture detailed access and modification events, ensuring that any future unauthorized attempts are quickly detected.
* Notify the security team and relevant stakeholders about the incident, providing them with details of the unauthorized modifications and actions taken to remediate the issue.
* If the unauthorized access is suspected to be part of a larger breach, escalate the incident to the incident response team for further investigation and potential involvement of law enforcement if necessary.
* Review and update incident response plans and playbooks to incorporate lessons learned from this incident, ensuring a more effective response to similar threats in the future.


## Setup [_setup_974]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5104]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.KEYVAULT/VAULTS/WRITE" and event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Unsecured Credentials
    * ID: T1552
    * Reference URL: [https://attack.mitre.org/techniques/T1552/](https://attack.mitre.org/techniques/T1552/)

* Sub-technique:

    * Name: Credentials In Files
    * ID: T1552.001
    * Reference URL: [https://attack.mitre.org/techniques/T1552/001/](https://attack.mitre.org/techniques/T1552/001/)




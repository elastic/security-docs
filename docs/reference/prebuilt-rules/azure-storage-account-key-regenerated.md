---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/azure-storage-account-key-regenerated.html
---

# Azure Storage Account Key Regenerated [azure-storage-account-key-regenerated]

Identifies a rotation to storage account access keys in Azure. Regenerating access keys can affect any applications or Azure services that are dependent on the storage account key. Adversaries may regenerate a key as a means of acquiring credentials to access systems and resources.

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

* [https://docs.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage?tabs=azure-portal](https://docs.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage?tabs=azure-portal)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Identity and Access Audit
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_206]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Storage Account Key Regenerated**

Azure Storage Account keys are critical credentials that grant access to storage resources. They are often used by applications and services to authenticate and interact with Azure Storage. Adversaries may regenerate these keys to gain unauthorized access, potentially disrupting services or exfiltrating data. The detection rule monitors for key regeneration events, flagging successful operations as potential indicators of credential misuse, thus enabling timely investigation and response.

**Possible investigation steps**

* Review the Azure activity logs to identify the specific storage account associated with the key regeneration event by examining the operation_name field for "MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION".
* Check the event.outcome field to confirm the success of the key regeneration and gather details about the user or service principal that initiated the action.
* Investigate the user or service principal’s recent activities in Azure to determine if there are any other suspicious actions or patterns that could indicate unauthorized access or misuse.
* Assess the impact on applications and services that rely on the affected storage account key by identifying dependencies and checking for any service disruptions or anomalies.
* Review access policies and permissions for the storage account to ensure they are appropriately configured and consider implementing additional security measures, such as Azure Key Vault, to manage and rotate keys securely.

**False positive analysis**

* Routine key rotation by administrators or automated scripts can trigger alerts. To manage this, identify and document regular key rotation schedules and exclude these events from alerts.
* Development and testing environments often regenerate keys frequently. Exclude these environments from alerts by filtering based on environment tags or resource names.
* Third-party integrations or services that require periodic key regeneration might cause false positives. Work with service owners to understand these patterns and create exceptions for known, legitimate services.
* Azure policies or compliance checks that enforce key rotation can also lead to false positives. Coordinate with compliance teams to align detection rules with policy schedules and exclude these events.
* Ensure that any automated processes that regenerate keys are logged and documented. Use this documentation to create exceptions for these processes in the detection rule.

**Response and remediation**

* Immediately revoke the regenerated storage account keys to prevent unauthorized access. This can be done through the Azure portal or using Azure CLI commands.
* Identify and update all applications and services that rely on the compromised storage account keys with new, secure keys to restore functionality and prevent service disruption.
* Conduct a thorough review of access logs and audit trails to identify any unauthorized access or data exfiltration attempts that may have occurred using the regenerated keys.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems or accounts have been compromised.
* Implement conditional access policies and multi-factor authentication (MFA) for accessing Azure resources to enhance security and prevent similar incidents.
* Review and update the storage account’s access policies and permissions to ensure that only authorized users and applications have the necessary access.
* Enhance monitoring and alerting mechanisms to detect future unauthorized key regeneration attempts promptly, ensuring timely response to potential threats.


## Setup [_setup_141]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_211]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION" and event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Steal Application Access Token
    * ID: T1528
    * Reference URL: [https://attack.mitre.org/techniques/T1528/](https://attack.mitre.org/techniques/T1528/)




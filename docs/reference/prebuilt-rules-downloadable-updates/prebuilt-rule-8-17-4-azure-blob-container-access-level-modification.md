---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-azure-blob-container-access-level-modification.html
---

# Azure Blob Container Access Level Modification [prebuilt-rule-8-17-4-azure-blob-container-access-level-modification]

Identifies changes to container access levels in Azure. Anonymous public read access to containers and blobs in Azure is a way to share data broadly, but can present a security risk if access to sensitive data is not managed judiciously.

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

* [https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent](https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Asset Visibility
* Tactic: Discovery
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4099]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Blob Container Access Level Modification**

Azure Blob Storage is a service for storing large amounts of unstructured data, where access levels can be configured to control data visibility. Adversaries may exploit misconfigured access levels to gain unauthorized access to sensitive data. The detection rule monitors changes in container access settings, focusing on successful modifications, to identify potential security risks associated with unauthorized access level changes.

**Possible investigation steps**

* Review the Azure activity logs to identify the specific storage account and container where the access level modification occurred, using the operation name "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE".
* Verify the identity of the user or service principal that performed the modification by examining the associated user information in the activity logs.
* Check the timestamp of the modification to determine if it aligns with any known maintenance windows or authorized changes.
* Investigate the previous access level settings of the container to assess the potential impact of the change, especially if it involved enabling anonymous public read access.
* Correlate the event with any other recent suspicious activities or alerts in the Azure environment to identify potential patterns or coordinated actions.
* Contact the owner of the storage account or relevant stakeholders to confirm whether the change was authorized and aligns with organizational policies.

**False positive analysis**

* Routine administrative changes to container access levels by authorized personnel can trigger alerts. To manage this, create exceptions for specific user accounts or roles that regularly perform these tasks.
* Automated scripts or tools used for managing storage configurations may cause false positives. Identify and exclude these scripts or tools from monitoring if they are verified as non-threatening.
* Scheduled updates or maintenance activities that involve access level modifications can be mistaken for unauthorized changes. Document and schedule these activities to align with monitoring rules, allowing for temporary exclusions during these periods.
* Changes made by trusted third-party services integrated with Azure Blob Storage might be flagged. Verify these services and exclude their operations from triggering alerts if they are deemed secure and necessary for business operations.

**Response and remediation**

* Immediately revoke public read access to the affected Azure Blob container to prevent unauthorized data exposure.
* Review the access logs to identify any unauthorized access or data exfiltration attempts during the period when the access level was modified.
* Notify the security team and relevant stakeholders about the incident, providing details of the unauthorized access level change and any potential data exposure.
* Conduct a thorough audit of all Azure Blob containers to ensure that access levels are configured according to the organization’s security policies and that no other containers are misconfigured.
* Implement additional monitoring and alerting for changes to access levels on Azure Blob containers to ensure rapid detection of any future unauthorized modifications.
* If sensitive data was exposed, initiate a data breach response plan, including notifying affected parties and regulatory bodies as required by law.
* Review and update access management policies and procedures to prevent recurrence, ensuring that only authorized personnel can modify container access levels.


## Setup [_setup_986]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5116]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE" and event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Cloud Service Discovery
    * ID: T1526
    * Reference URL: [https://attack.mitre.org/techniques/T1526/](https://attack.mitre.org/techniques/T1526/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Exploit Public-Facing Application
    * ID: T1190
    * Reference URL: [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)




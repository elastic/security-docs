---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-azure-event-hub-authorization-rule-created-or-updated.html
---

# Azure Event Hub Authorization Rule Created or Updated [prebuilt-rule-8-17-4-azure-event-hub-authorization-rule-created-or-updated]

Identifies when an Event Hub Authorization Rule is created or updated in Azure. An authorization rule is associated with specific rights, and carries a pair of cryptographic keys. When you create an Event Hubs namespace, a policy rule named RootManageSharedAccessKey is created for the namespace. This has manage permissions for the entire namespace and it’s recommended that you treat this rule like an administrative root account and don’t use it in your application.

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

* [https://docs.microsoft.com/en-us/azure/event-hubs/authorize-access-shared-access-signature](https://docs.microsoft.com/en-us/azure/event-hubs/authorize-access-shared-access-signature)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Use Case: Log Auditing
* Tactic: Collection
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4080]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Event Hub Authorization Rule Created or Updated**

Azure Event Hub Authorization Rules manage access to Event Hubs via cryptographic keys, akin to administrative credentials. Adversaries may exploit these rules to gain unauthorized access or escalate privileges, potentially exfiltrating data. The detection rule monitors for the creation or modification of these rules, flagging successful operations to identify potential misuse or unauthorized changes.

**Possible investigation steps**

* Review the Azure activity logs to identify the user or service principal associated with the operation by examining the `azure.activitylogs.operation_name` and `event.outcome` fields.
* Check the timestamp of the event to determine when the authorization rule was created or updated, and correlate this with any other suspicious activities around the same time.
* Investigate the specific Event Hub namespace affected by the rule change to understand its role and importance within the organization.
* Verify if the `RootManageSharedAccessKey` or any other high-privilege authorization rule was involved, as these carry significant risk if misused.
* Assess the necessity and legitimacy of the rule change by contacting the user or team responsible for the Event Hub namespace to confirm if the change was authorized and aligns with operational needs.
* Examine any subsequent access patterns or data transfers from the affected Event Hub to detect potential data exfiltration or misuse following the rule change.

**False positive analysis**

* Routine administrative updates to authorization rules by IT staff can trigger alerts. To manage this, create exceptions for known administrative accounts or scheduled maintenance windows.
* Automated scripts or deployment tools that update authorization rules as part of regular operations may cause false positives. Identify these scripts and exclude their activity from alerts by filtering based on their service principal or user identity.
* Changes made by trusted third-party services integrated with Azure Event Hub might be flagged. Verify these services and exclude their operations by adding them to an allowlist.
* Frequent updates during development or testing phases can lead to false positives. Consider setting up separate monitoring profiles for development environments to reduce noise.
* Legitimate changes made by users with appropriate permissions might be misinterpreted as threats. Regularly review and update the list of authorized users to ensure only necessary personnel have access, and exclude their actions from alerts.

**Response and remediation**

* Immediately revoke or rotate the cryptographic keys associated with the affected Event Hub Authorization Rule to prevent unauthorized access.
* Review the Azure Activity Logs to identify any unauthorized access or data exfiltration attempts that may have occurred using the compromised authorization rule.
* Implement conditional access policies to restrict access to Event Hub Authorization Rules based on user roles and network locations.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems or data have been compromised.
* Conduct a security review of all Event Hub Authorization Rules to ensure that only necessary permissions are granted and that the RootManageSharedAccessKey is not used in applications.
* Enhance monitoring and alerting for changes to authorization rules by integrating with a Security Information and Event Management (SIEM) system to detect similar threats in the future.


## Setup [_setup_969]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5097]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.EVENTHUB/NAMESPACES/AUTHORIZATIONRULES/WRITE" and event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data from Cloud Storage
    * ID: T1530
    * Reference URL: [https://attack.mitre.org/techniques/T1530/](https://attack.mitre.org/techniques/T1530/)

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Transfer Data to Cloud Account
    * ID: T1537
    * Reference URL: [https://attack.mitre.org/techniques/T1537/](https://attack.mitre.org/techniques/T1537/)




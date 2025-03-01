---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/gcp-storage-bucket-deletion.html
---

# GCP Storage Bucket Deletion [gcp-storage-bucket-deletion]

Identifies when a Google Cloud Platform (GCP) storage bucket is deleted. An adversary may delete a storage bucket in order to disrupt their target’s business operations.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-gcp*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cloud.google.com/storage/docs/key-terms#buckets](https://cloud.google.com/storage/docs/key-terms#buckets)

**Tags**:

* Domain: Cloud
* Data Source: GCP
* Data Source: Google Cloud Platform
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_371]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Storage Bucket Deletion**

Google Cloud Platform (GCP) storage buckets are essential for storing and managing data in cloud environments. Adversaries may target these buckets to delete critical data, causing operational disruptions. The detection rule monitors audit logs for deletion actions, identifying potential malicious activity by flagging events where storage buckets are removed, thus enabling timely investigation and response.

**Possible investigation steps**

* Review the audit logs for the specific event.action "storage.buckets.delete" to identify the user or service account responsible for the deletion.
* Check the timestamp of the deletion event to determine when the bucket was deleted and correlate it with any other suspicious activities around that time.
* Investigate the IP address and location from which the deletion request originated to assess if it aligns with expected access patterns.
* Examine the permissions and roles assigned to the user or service account involved in the deletion to determine if they had legitimate access.
* Look for any recent changes in IAM policies or permissions that might have allowed unauthorized access to the storage bucket.
* Contact the relevant stakeholders or data owners to confirm if the deletion was authorized or if it was unexpected.

**False positive analysis**

* Routine maintenance or scheduled deletions by authorized personnel can trigger false positives. To manage this, create exceptions for known maintenance windows or specific user accounts responsible for these tasks.
* Automated scripts or applications that manage storage lifecycle policies might delete buckets as part of their normal operation. Identify these scripts and exclude their actions from triggering alerts by using service account identifiers.
* Development or testing environments often involve frequent creation and deletion of storage buckets. Exclude these environments from monitoring by filtering based on project IDs or environment tags.
* Organizational policy changes that involve restructuring storage resources can lead to legitimate bucket deletions. Coordinate with relevant teams to update detection rules temporarily during such changes.

**Response and remediation**

* Immediately isolate the affected GCP project to prevent further unauthorized access or actions. This can be done by revoking access keys and permissions for any suspicious accounts identified in the audit logs.
* Restore the deleted storage bucket from the most recent backup to minimize data loss and operational disruption. Ensure that the backup is clean and free from any malicious alterations.
* Conduct a thorough review of IAM roles and permissions associated with the affected storage bucket to ensure that only authorized users have the necessary access. Implement the principle of least privilege.
* Enable versioning on critical storage buckets to protect against accidental or malicious deletions in the future, allowing for easier recovery of deleted objects.
* Set up alerts for any future deletion actions on storage buckets to ensure immediate awareness and response to similar threats.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems or data were compromised.
* Document the incident, including actions taken and lessons learned, to improve response strategies and update incident response plans for future reference.


## Setup [_setup_235]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_403]

```js
event.dataset:gcp.audit and event.action:"storage.buckets.delete"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Destruction
    * ID: T1485
    * Reference URL: [https://attack.mitre.org/techniques/T1485/](https://attack.mitre.org/techniques/T1485/)




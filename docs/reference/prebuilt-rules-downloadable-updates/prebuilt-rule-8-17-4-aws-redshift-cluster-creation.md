---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-redshift-cluster-creation.html
---

# AWS Redshift Cluster Creation [prebuilt-rule-8-17-4-aws-redshift-cluster-creation]

Identifies the creation of an Amazon Redshift cluster. Unexpected creation of this cluster by a non-administrative user may indicate a permission or role issue with current users. If unexpected, the resource may not properly be configured and could introduce security vulnerabilities.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html](https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS Redshift
* Use Case: Asset Visibility
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4053]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS Redshift Cluster Creation**

Amazon Redshift is a data warehousing service that allows for scalable data storage and analysis. In a secure environment, only authorized users should create Redshift clusters. Adversaries might exploit misconfigured permissions to create clusters, potentially leading to data exfiltration or unauthorized data processing. The detection rule monitors for successful cluster creation events, especially by non-admin users, to identify potential misuse or misconfigurations.

**Possible investigation steps**

* Review the CloudTrail logs for the event.dataset:aws.cloudtrail and event.provider:redshift.amazonaws.com to confirm the details of the CreateCluster event, including the timestamp and the user who initiated the action.
* Identify the IAM role or user associated with the event.action:CreateCluster and verify if this user is expected to have permissions to create Redshift clusters. Check for any recent changes to their permissions or roles.
* Investigate the event.outcome:success to ensure that the cluster creation was indeed successful and determine the region and account where the cluster was created.
* Examine the configuration of the newly created Redshift cluster to ensure it adheres to security best practices, such as encryption settings, VPC configurations, and access controls.
* Cross-reference the user activity with other logs or alerts to identify any unusual patterns or behaviors that might indicate misuse or compromise, such as multiple cluster creation attempts or access from unfamiliar IP addresses.
* Contact the user or team responsible for the account to verify if the cluster creation was intentional and authorized, and document their response for future reference.

**False positive analysis**

* Routine maintenance or testing activities by non-admin users can trigger alerts. To manage this, create exceptions for specific users or roles known to perform these tasks regularly.
* Automated scripts or third-party tools that create clusters as part of their normal operation may cause false positives. Identify these tools and exclude their associated user accounts or roles from the detection rule.
* Development or staging environments where non-admin users are permitted to create clusters for testing purposes can lead to alerts. Implement environment-specific exclusions to prevent unnecessary alerts.
* Temporary permissions granted to non-admin users for specific projects can result in cluster creation alerts. Monitor and document these permissions, and adjust the detection rule to account for these temporary changes.

**Response and remediation**

* Immediately isolate the Redshift cluster to prevent any unauthorized access or data exfiltration. This can be done by modifying the security group rules to restrict inbound and outbound traffic.
* Review the IAM roles and permissions associated with the user who created the cluster. Revoke any unnecessary permissions and ensure that the principle of least privilege is enforced.
* Conduct a thorough audit of recent CloudTrail logs to identify any other unauthorized activities or anomalies associated with the same user or related accounts.
* If data exfiltration is suspected, initiate a data integrity check and consider restoring from a known good backup to ensure no data tampering has occurred.
* Notify the security team and relevant stakeholders about the incident for further investigation and to determine if additional security measures are needed.
* Implement additional monitoring and alerting for Redshift cluster creation events, especially focusing on non-administrative users, to quickly detect similar activities in the future.
* Consider enabling multi-factor authentication (MFA) for all users with permissions to create or modify Redshift clusters to add an extra layer of security.


## Setup [_setup_950]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5070]

```js
event.dataset:aws.cloudtrail and event.provider:redshift.amazonaws.com and event.action:CreateCluster and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)




---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-rds-db-instance-restored.html
---

# AWS RDS DB Instance Restored [prebuilt-rule-8-17-4-aws-rds-db-instance-restored]

An adversary with a set of compromised credentials may attempt to make copies of running or deleted RDS databases in order to evade defense mechanisms or access data. This rule identifies successful attempts to restore a DB instance using the RDS `RestoreDBInstanceFromDBSnapshot` or `RestoreDBInstanceFromS3` API operations.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_RestoreDBInstanceFromDBSnapshot.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_RestoreDBInstanceFromDBSnapshot.md)
* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_RestoreDBInstanceFromS3.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_RestoreDBInstanceFromS3.md)
* [https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/rds__explore_snapshots/main.py](https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/rds__explore_snapshots/main.py)
* [https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-post-exploitation/aws-rds-post-exploitation#rds-createdbsnapshot-rds-restoredbinstancefromdbsnapshot-rds-modifydbinstance](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-post-exploitation/aws-rds-post-exploitation#rds-createdbsnapshot-rds-restoredbinstancefromdbsnapshot-rds-modifydbinstance)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS RDS
* Use Case: Asset Visibility
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Austin Songer
* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3992]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS RDS DB Instance Restored**

Amazon RDS (Relational Database Service) allows users to set up, operate, and scale databases in the cloud. Adversaries may exploit RDS by restoring DB instances from snapshots or S3 to access sensitive data or bypass security controls. The detection rule identifies successful restoration attempts, signaling potential unauthorized access or data exfiltration activities, by monitoring specific API operations and outcomes.

**Possible investigation steps**

* Review the CloudTrail logs to identify the user or role associated with the successful `RestoreDBInstanceFromDBSnapshot` or `RestoreDBInstanceFromS3` API call by examining the `user.identity` field.
* Check the source IP address and location from which the API call was made using the `sourceIPAddress` field to determine if it aligns with expected or known locations.
* Investigate the timing of the restoration event by looking at the `@timestamp` field to see if it coincides with any other suspicious activities or anomalies in the environment.
* Examine the specific DB instance details restored, such as the DB instance identifier, to assess the sensitivity of the data involved and potential impact.
* Verify if there are any associated alerts or logs indicating unauthorized access or data exfiltration attempts around the same time frame.
* Contact the user or team responsible for the credentials used, if legitimate, to confirm whether the restoration was authorized and intended.

**False positive analysis**

* Routine database maintenance or testing activities may trigger the rule. Organizations should identify and document regular restoration activities performed by authorized personnel and exclude these from alerts.
* Automated backup and restore processes used for disaster recovery or data migration can result in false positives. Users should configure exceptions for known automated processes by filtering based on specific user accounts or roles.
* Development and staging environments often involve frequent restoration of databases for testing purposes. Exclude these environments by identifying and filtering out specific instance identifiers or tags associated with non-production environments.
* Scheduled tasks or scripts that restore databases as part of regular operations can be mistaken for unauthorized activity. Ensure these tasks are well-documented and create exceptions based on the source IP or IAM role used for these operations.
* Third-party services or integrations that require database restoration for functionality may trigger alerts. Verify these services and exclude their associated actions by identifying their unique user agents or API keys.

**Response and remediation**

* Immediately isolate the restored RDS instance to prevent unauthorized access. This can be done by modifying the security group rules to restrict inbound and outbound traffic.
* Conduct a thorough review of CloudTrail logs to identify the source of the compromised credentials and any other suspicious activities associated with the same user or account.
* Revoke the compromised credentials and issue new credentials for the affected user or service account. Ensure that multi-factor authentication (MFA) is enabled for all accounts.
* Notify the security team and relevant stakeholders about the incident, providing details of the unauthorized restoration and any potential data exposure.
* Perform a security assessment of the restored RDS instance to identify any unauthorized changes or data exfiltration. This includes checking for unusual queries or data exports.
* Implement additional monitoring and alerting for similar API operations to detect future unauthorized restoration attempts promptly.
* Review and update IAM policies to ensure that only authorized users have the necessary permissions to restore RDS instances, reducing the risk of future incidents.


## Rule query [_rule_query_5009]

```js
any where event.dataset == "aws.cloudtrail"
    and event.provider == "rds.amazonaws.com"
    and event.action in ("RestoreDBInstanceFromDBSnapshot", "RestoreDBInstanceFromS3")
    and event.outcome == "success"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Cloud Compute Infrastructure
    * ID: T1578
    * Reference URL: [https://attack.mitre.org/techniques/T1578/](https://attack.mitre.org/techniques/T1578/)

* Sub-technique:

    * Name: Create Cloud Instance
    * ID: T1578.002
    * Reference URL: [https://attack.mitre.org/techniques/T1578/002/](https://attack.mitre.org/techniques/T1578/002/)

* Sub-technique:

    * Name: Revert Cloud Instance
    * ID: T1578.004
    * Reference URL: [https://attack.mitre.org/techniques/T1578/004/](https://attack.mitre.org/techniques/T1578/004/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-rds-db-instance-or-cluster-password-modified.html
---

# AWS RDS DB Instance or Cluster Password Modified [aws-rds-db-instance-or-cluster-password-modified]

Identifies the modification of the master password for an AWS RDS DB instance or cluster. DB instances may contain sensitive data that can be abused if accessed by unauthorized actors. Amazon RDS API operations never return the password, so this operation provides a means to regain access if the password is lost. Adversaries with the proper permissions can take advantage of this to evade defenses and gain unauthorized access to a DB instance or cluster to support persistence mechanisms or privilege escalation.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.md)
* [https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.DBInstance.Modifying.html](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.DBInstance.Modifying.md)
* [https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-rds-privesc#rds-modifydbinstance](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-rds-privesc#rds-modifydbinstance)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS RDS
* Resources: Investigation Guide
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Privilege Escalation
* Tactic: Defense Evasion

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_69]

**Triage and analysis**

**Investigating AWS RDS DB Instance or Cluster Password Modified**

This rule identifies when an RDS DB instance or cluster password is modified. While changing the master password is a legitimate means to regain access in the case of a lost password, adversaries may exploit this feature to maintain persistence or evade defenses in a compromised environment.

**Possible Investigation Steps**

* ***Identify the Actor***: Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` fields to identify who made the change. Verify if this actor typically performs such actions and if they have the necessary permissions.
* ***Review the Modification Event***: Identify the DB instance involved and review the event details. Look for `ModifyDBInstance` actions where the masterUserPassword parameter was changed.
* ***Request and Response Parameters***: Check the `aws.cloudtrail.request_parameters` field in the CloudTrail event to identify the DB Instance Identifier and any other modifications made to the instance.
* ***Verify the Modified Instance***: Check the DB instance that was modified and its contents to determine the sensitivity of the data stored within it.
* ***Contextualize with Recent Changes***: Compare this modification event against recent changes in RDS DB or Cluster configurations and deployments. Look for any other recent permissions changes or unusual administrative actions.
* ***Correlate with Other Activities***: Search for related CloudTrail events before and after this change to see if the same actor or IP address engaged in other potentially suspicious activities.
* ***Interview Relevant Personnel***: If the modification was initiated by a user, verify the intent and authorization for this action with the person or team responsible for managing DB instances.

**False Positive Analysis**

* ***Legitimate Instance Modification***: Confirm if the DB instance modification aligns with legitimate tasks.
* ***Consistency Check***: Compare the action against historical data of similar actions performed by the user or within the organization. If the action is consistent with past legitimate activities, it might indicate a false alarm.

**Response and Remediation**

* ***Immediate Review and Reversal***: If the change was unauthorized, update the instance password. If the master user password was managed with AWS Secrets Manager, determine whether the `manageMasterUserPassword` attribute was changed to false and revert if necessary.
* ***Enhance Monitoring and Alerts***: Adjust monitoring systems to alert on similar actions, especially those involving sensitive data or permissions.
* ***Audit Instances and Policies***: Conduct a comprehensive audit of all instances and associated policies to ensure they adhere to the principle of least privilege.
* ***Policy Update***: Review and possibly update your organization’s policies on DB instance access to tighten control and prevent unauthorized access.
* ***Incident Response***: If malicious intent is confirmed, consider it a data breach incident and initiate the incident response protocol. This includes further investigation, containment, and recovery.

**Additional Information:**

For further guidance on managing DB instances and securing AWS environments, refer to the [AWS RDS documentation](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_RDS_Managing.md) and AWS best practices for security. Additionally, consult the following resources for specific details on DB instance security: - [AWS RDS ModifyDBInstance](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.md) - [Amazon RDS and Secrets Manager](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-secrets-manager.md)


## Rule query [_rule_query_72]

```js
any where event.dataset == "aws.cloudtrail"
    and event.provider == "rds.amazonaws.com"
    and event.action in ("ModifyDBInstance", "ModifyDBCluster")
    and event.outcome == "success"
    and stringContains(aws.cloudtrail.request_parameters, "masterUserPassword=*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Sub-technique:

    * Name: Additional Cloud Credentials
    * ID: T1098.001
    * Reference URL: [https://attack.mitre.org/techniques/T1098/001/](https://attack.mitre.org/techniques/T1098/001/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)




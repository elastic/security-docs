---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-rds-db-instance-or-cluster-deletion-protection-disabled.html
---

# AWS RDS DB Instance or Cluster Deletion Protection Disabled [prebuilt-rule-8-17-4-aws-rds-db-instance-or-cluster-deletion-protection-disabled]

Identifies the modification of an AWS RDS DB instance or cluster to remove the deletionProtection feature. Deletion protection is enabled automatically for instances set up through the console and can be used to protect them from unintentional deletion activity. If disabled an instance or cluster can be deleted, destroying sensitive or critical information. Adversaries with the proper permissions can take advantage of this to set up future deletion events against a compromised environment.

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
* [https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS RDS
* Resources: Investigation Guide
* Use Case: Threat Detection
* Tactic: Impact

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4027]

**Triage and analysis**

**Investigating AWS RDS DB Instance or Cluster Deletion Protection Disabled**

This rule identifies when the deletion protection feature is removed from an RDS DB instance or cluster. Removing deletion protection is a prerequisite for deleting a DB instance. Adversaries may exploit this feature to permanently delete data in a compromised environment.

**Possible Investigation Steps**

* ***Identify the Actor***: Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` fields to identify who made the change. Verify if this actor typically performs such actions and if they have the necessary permissions.
* ***Review the Modification Event***: Identify the DB instance involved and review the event details. Look for `ModifyDBInstance` actions where the deletionProtection parameter was changed.
* ***Request and Response Parameters***: Check the `aws.cloudtrail.request_parameters` field in the CloudTrail event to identify the DB instance or cluster identifier and any other modifications made to the instance.
* ***Verify the Modified Instance***: Check the DB instance that was modified and its contents to determine the sensitivity of the data stored within it.
* ***Contextualize with Recent Changes***: Compare this modification event against recent changes in RDS DB instance or cluster configurations and deployments. Look for any other recent permissions changes or unusual administrative actions.
* ***Correlate with Other Activities***: Search for related CloudTrail events before and after this change to see if the same actor or IP address engaged in other potentially suspicious activities.
* ***Interview Relevant Personnel***: If the modification was initiated by a user, verify the intent and authorization for this action with the person or team responsible for managing DB instances.

**False Positive Analysis**

* ***Legitimate Instance Modification***: Confirm if the DB instance modification aligns with legitimate tasks.
* ***Consistency Check***: Compare the action against historical data of similar actions performed by the user or within the organization. If the action is consistent with past legitimate activities, it might indicate a false alarm.

**Response and Remediation**

* ***Immediate Review and Reversal***: If the change was unauthorized, reset deletionProtection to true.
* ***Enhance Monitoring and Alerts***: Adjust monitoring systems to alert on similar actions, especially those involving sensitive data or permissions.
* ***Audit Instances and Policies***: Conduct a comprehensive audit of all instances and associated policies to ensure they adhere to the principle of least privilege.
* ***Policy Update***: Review and possibly update your organization’s policies on DB instance access to tighten control and prevent unauthorized access.
* ***Incident Response***: If malicious intent is confirmed, consider it a data breach incident and initiate the incident response protocol. This includes further investigation, containment, and recovery.

**Additional Information:**

For further guidance on managing DB instances and securing AWS environments, refer to the [AWS RDS documentation](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_RDS_Managing.md) and AWS best practices for security. Additionally, consult the following resources for specific details on DB instance security: - [AWS RDS ModifyDBInstance](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.md) - [Deleting AWS RDS DB Instance](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.md)


## Rule query [_rule_query_5044]

```js
any where event.dataset == "aws.cloudtrail"
    and event.provider == "rds.amazonaws.com"
    and event.action in ("ModifyDBInstance", "ModifyDBCluster")
    and event.outcome == "success"
    and stringContains(aws.cloudtrail.request_parameters, "deletionProtection=false")
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




---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-iam-group-deletion.html
---

# AWS IAM Group Deletion [prebuilt-rule-8-17-4-aws-iam-group-deletion]

Identifies the deletion of a specified AWS Identity and Access Management (IAM) resource group. Deleting a resource group does not delete resources that are members of the group; it only deletes the group structure.

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

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/delete-group.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/delete-group.md)
* [https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteGroup.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteGroup.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS IAM
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4023]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS IAM Group Deletion**

AWS IAM groups facilitate user management by organizing users with similar permissions. Adversaries might exploit group deletion to disrupt access controls, potentially leading to unauthorized access or service disruption. The detection rule monitors successful group deletions via AWS CloudTrail, flagging potential misuse by correlating specific IAM actions and outcomes, thus aiding in timely threat identification.

**Possible investigation steps**

* Review the AWS CloudTrail logs to identify the user or role that performed the DeleteGroup action by examining the userIdentity field.
* Check the event time to determine when the group deletion occurred and correlate it with any other suspicious activities around the same timeframe.
* Investigate the specific IAM group that was deleted to understand its purpose and the permissions it granted by reviewing historical IAM policies and group membership.
* Assess the impact of the group deletion by identifying any users or services that might have been affected due to the loss of group-based permissions.
* Verify if the group deletion was authorized by cross-referencing with change management records or contacting the responsible team or individual.
* Look for any patterns or repeated occurrences of similar actions in the logs to identify potential malicious behavior or misconfigurations.

**False positive analysis**

* Routine administrative tasks may trigger alerts when IAM groups are deleted as part of regular maintenance or restructuring. To manage this, create exceptions for known maintenance periods or specific administrative accounts.
* Automated scripts or tools that manage IAM resources might delete groups as part of their normal operation. Identify these scripts and exclude their actions from triggering alerts by using specific user or role identifiers.
* Temporary groups created for short-term projects or testing purposes might be deleted frequently. Document these groups and exclude their deletion from monitoring by using naming conventions or tags.
* Changes in organizational structure or policy might necessitate the deletion of certain groups. Coordinate with relevant teams to anticipate these changes and adjust monitoring rules accordingly.

**Response and remediation**

* Immediately revoke any active sessions and access keys for users who were part of the deleted IAM group to prevent unauthorized access.
* Restore the deleted IAM group from a backup or recreate it with the same permissions to ensure continuity of access for legitimate users.
* Conduct a review of recent IAM activity logs to identify any unauthorized or suspicious actions that may have preceded the group deletion.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation.
* Implement additional monitoring on IAM activities, especially focusing on group management actions, to detect similar threats in the future.
* Review and tighten IAM policies and permissions to ensure that only authorized personnel can delete IAM groups.
* If malicious intent is suspected, escalate the incident to the incident response team for a comprehensive investigation and potential legal action.


## Setup [_setup_937]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5040]

```js
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:DeleteGroup and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Account Access Removal
    * ID: T1531
    * Reference URL: [https://attack.mitre.org/techniques/T1531/](https://attack.mitre.org/techniques/T1531/)




---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-first-time-aws-cloudformation-stack-creation-by-user.html
---

# First Time AWS Cloudformation Stack Creation by User [prebuilt-rule-8-17-4-first-time-aws-cloudformation-stack-creation-by-user]

This rule detects the first time a principal calls AWS Cloudwatch `CreateStack` or `CreateStackSet` API. Cloudformation is used to create a single collection of cloud resources called a stack, via a defined template file. An attacker with the appropriate privileges could leverage Cloudformation to create specific resources needed to further exploit the environment. This is a new terms rule that looks for the first instance of this behavior in the last 10 days for a role or IAM user within a particular account.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-cli-creating-stack.html/](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-cli-creating-stack.md/)
* [https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-concepts.html/](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-concepts.md/)
* [https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateStack.html/](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateStack.md/)
* [https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateStackSet.html/](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateStackSet.md/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: Cloudformation
* Use Case: Asset Visibility
* Tactic: Execution
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4008]

**Triage and analysis**

[TBC: QUOTE]
**Investigating First Time AWS Cloudformation Stack Creation by User**

AWS CloudFormation automates the setup of cloud resources using templates, streamlining infrastructure management. Adversaries with access can exploit this to deploy malicious resources, escalating their control. The detection rule identifies unusual activity by flagging the initial use of stack creation APIs by a user, helping to spot potential unauthorized actions early.

**Possible investigation steps**

* Review the CloudTrail logs for the specific event.dataset:aws.cloudtrail and event.provider:cloudformation.amazonaws.com to identify the user or role that initiated the CreateStack or CreateStackSet action.
* Verify the IAM permissions of the user or role involved in the event to ensure they have the appropriate level of access and determine if the action aligns with their typical responsibilities.
* Examine the stack template used in the CreateStack or CreateStackSet action to identify any unusual or unauthorized resources being provisioned.
* Check the event.outcome:success field to confirm the stack creation was successful and investigate any related resources that were deployed as part of the stack.
* Correlate the timing of the stack creation with other logs or alerts to identify any suspicious activity or patterns that might indicate malicious intent.
* Investigate the account’s recent activity history to determine if there have been any other first-time or unusual actions by the same user or role.

**False positive analysis**

* Routine infrastructure updates by authorized users may trigger the rule. To manage this, maintain a list of users or roles that regularly perform these updates and create exceptions for them.
* Automated deployment tools or scripts that use CloudFormation for legitimate purposes can cause false positives. Identify these tools and exclude their associated IAM roles or users from the rule.
* New team members or roles onboarding into cloud management tasks might be flagged. Implement a process to review and whitelist these users after verifying their activities.
* Scheduled or periodic stack creations for testing or development environments can be mistaken for suspicious activity. Document these schedules and exclude the relevant users or roles from the rule.
* Third-party services or integrations that require stack creation permissions could be misidentified. Ensure these services are documented and their actions are excluded from triggering the rule.

**Response and remediation**

* Immediately isolate the IAM user or role that initiated the stack creation to prevent further unauthorized actions. This can be done by revoking permissions or disabling the account temporarily.
* Review the created stack and stack set for any unauthorized or suspicious resources. Identify and terminate any resources that are not part of the expected infrastructure.
* Conduct a thorough audit of recent IAM activity to identify any other unusual or unauthorized actions that may indicate further compromise.
* If malicious activity is confirmed, escalate the incident to the security operations team for a full investigation and potential involvement of incident response teams.
* Implement additional monitoring and alerting for the affected account to detect any further unauthorized attempts to use CloudFormation or other critical AWS services.
* Review and tighten IAM policies and permissions to ensure that only necessary privileges are granted, reducing the risk of exploitation by adversaries.
* Consider enabling AWS CloudTrail logging and AWS Config rules to maintain a detailed record of all API activity and configuration changes for ongoing monitoring and compliance.


## Rule query [_rule_query_5025]

```js
event.dataset:aws.cloudtrail and event.provider:cloudformation.amazonaws.com and
    event.action: (CreateStack or CreateStackSet) and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)




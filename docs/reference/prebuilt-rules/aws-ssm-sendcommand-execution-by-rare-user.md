---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-ssm-sendcommand-execution-by-rare-user.html
---

# AWS SSM `SendCommand` Execution by Rare User [aws-ssm-sendcommand-execution-by-rare-user]

Detects the execution of commands or scripts on EC2 instances using AWS Systems Manager (SSM), such as `RunShellScript`, `RunPowerShellScript` or custom documents. While legitimate users may employ these commands for management tasks, they can also be exploited by attackers with credentials to establish persistence, install malware, or execute reverse shells for further access to compromised instances. This is a [New Terms](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-new-terms-rule) rule that looks for the first instance of this behavior by the `aws.cloudtrail.user_identity.arn` field in the last 7 days.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-plugins.html](https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-plugins.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS SSM
* Use Case: Log Auditing
* Use Case: Threat Detection
* Tactic: Execution
* Resources: Investigation Guide

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_95]

**Triage and analysis**

**Investigating AWS SSM `SendCommand` Execution by Rare User**

This rule detects the execution of commands or scripts on EC2 instances using AWS Systems Manager (SSM) by an unexpected or new user. The SSM `SendCommand` action can enable remote command execution, which adversaries may exploit to install backdoors, deploy malware, or interact with compromised instances through reverse shells.

**Possible Investigation Steps**

* ***Identify the Target Instance***:
* ***Instance ID***: Review the `aws.cloudtrail.flattened.request_parameters.targets` field to identify which EC2 instances were targeted by this command. Confirm if these instances are expected to be managed through SSM.
* ***Document Used***: Check the `aws.cloudtrail.flattened.request_parameters.documentName` field, which specifies the document or script being executed. Commands such as `RunShellScript` or `RunPowerShellScript` can indicate interactive sessions or script-based interactions.
* ***Review User Context***:
* ***User Identity***: Inspect the `aws.cloudtrail.user_identity.arn` field to determine the user or role executing the `SendCommand`. If this user is not typically involved in EC2 or SSM interactions, this could indicate unauthorized access.
* ***Access Patterns***: Validate whether the user typically has permissions to perform `SendCommand` operations on instances and whether the frequency of this action matches expected behavior.
* ***Analyze Command Parameters***:
* ***Document Contents***: While the exact command may not be visible in CloudTrail, use logs to determine the purpose of the script, especially if the document name suggests encryption, data transfer, or reverse shell capabilities.
* ***Timing and Context***: Compare this command execution with other recent SSM actions in your environment. A single `SendCommand` event by an unusual user can indicate an early stage of a larger attack.
* ***Check User Agent and Source IP***:
* ***User Agent Analysis***: Review the `user_agent.original` field to verify the tool or client used (e.g., `aws-cli`). This can provide insight into whether this action was automated, scripted, or executed manually.
* ***Source IP and Geolocation***: Use `source.address` and `source.geo` fields to check if the IP address and geolocation align with expected regions for your organization. Unusual IP addresses or locations can indicate external adversaries.
* ***Evaluate for Persistence Indicators***:
* ***Command Consistency***: Investigate if this action is part of a recurring pattern, such as repeated command executions across instances, which may suggest an attempt to maintain access.
* ***Permissions***: Ensure that the IAM policies associated with the user limit `SendCommand` actions to necessary use cases. Consider adding alerts for commands executed by users with minimal roles or permissions.
* ***Correlate with Other CloudTrail Events***:
* ***Cross-Reference SSM Actions***: Look for other recent SSM actions like `CreateDocument`, `UpdateDocument`, or additional `SendCommand` events that could indicate preparation for further exploitation.
* ***Monitor Data Access or Modification***: Correlate with `S3` access patterns, IAM changes, or EC2 modifications in recent events to detect broader malicious activities.

**False Positive Analysis**

* ***Routine Automation***: SSM `SendCommand` may be used by automation scripts or management tools. Verify if this event aligns with known, routine automated workflows.
* ***Maintenance Activity***: Confirm if legitimate administrative activities, such as patching or updates, are expected at this time, which may involve similar commands executed on multiple instances.

**Response and Remediation**

* ***Limit SSM Permissions***: If unauthorized, immediately revoke `SendCommand` permissions from the user or role to prevent further access.
* ***Quarantine Target Instance***: If malicious behavior is confirmed, isolate the affected EC2 instance(s) to limit lateral movement or data exfiltration.
* ***Investigate and Contain User Account***: If the action was performed by a compromised account, review recent activity and reset access credentials as necessary.
* ***Audit SSM and IAM Configurations***: Periodically review permissions associated with SSM usage and ensure least privilege access principles are in place.

**Additional Information**

For further details on managing AWS SSM and security best practices for EC2 instances, refer to the [AWS Systems Manager Documentation](https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-plugins.md) and AWS best practices.


## Rule query [_rule_query_99]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: "ssm.amazonaws.com"
    and event.action: "SendCommand"
    and event.outcome: "success"
    and not aws.cloudtrail.user_identity.arn: *AWSServiceRoleForAmazonSSM/StateManagerService*
    and not source.address: (
      "ssm-guiconnect.amazonaws.com" or
      "ssm.amazonaws.com" or
      "inspector2.amazonaws.com"
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Cloud Administration Command
    * ID: T1651
    * Reference URL: [https://attack.mitre.org/techniques/T1651/](https://attack.mitre.org/techniques/T1651/)




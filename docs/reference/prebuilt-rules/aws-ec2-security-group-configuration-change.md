---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-ec2-security-group-configuration-change.html
---

# AWS EC2 Security Group Configuration Change [aws-ec2-security-group-configuration-change]

Identifies a change to an AWS Security Group Configuration. A security group is like a virtual firewall, and modifying configurations may allow unauthorized access. Threat actors may abuse this to establish persistence, exfiltrate data, or pivot in an AWS environment.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2-security-groups.html](https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2-security-groups.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS EC2
* Use Case: Network Security Monitoring
* Resources: Investigation Guide
* Tactic: Persistence
* Tactic: Defense Evasion

**Version**: 208

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_33]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS EC2 Security Group Configuration Change**

AWS EC2 Security Groups act as virtual firewalls, controlling inbound and outbound traffic to instances. Adversaries may exploit changes in these configurations to gain unauthorized access, maintain persistence, or exfiltrate data. The detection rule monitors successful modifications to security group settings, such as rule changes or new group creation, to identify potential security breaches and unauthorized access attempts.

**Possible investigation steps**

* Review the CloudTrail logs for the specific event.dataset "aws.cloudtrail" to identify the exact changes made to the security group configuration.
* Examine the event.provider "ec2.amazonaws.com" and event.action fields to determine the type of action performed, such as "AuthorizeSecurityGroupEgress" or "ModifySecurityGroupRules", to understand the nature of the change.
* Check the event.outcome field to confirm the success of the action and correlate it with any suspicious activity or unauthorized access attempts.
* Investigate the IAM user or role associated with the change to verify if the action aligns with their typical behavior and permissions.
* Analyze the timing and context of the change to see if it coincides with any other unusual activities or alerts in the AWS environment.
* Assess the impact of the security group change on the overall security posture, including potential exposure of sensitive resources or data.
* If necessary, consult with the responsible team or individual to validate the legitimacy of the change and ensure it was authorized.

**False positive analysis**

* Routine administrative changes to security groups by authorized personnel can trigger alerts. To manage this, maintain a list of known IP addresses and users who regularly perform these tasks and create exceptions for their activities.
* Automated scripts or tools used for infrastructure management may frequently modify security group settings. Identify these tools and exclude their actions from triggering alerts by using their specific identifiers or tags.
* Scheduled updates or deployments that involve security group modifications can result in false positives. Document these schedules and adjust the monitoring rules to account for these expected changes during specific time windows.
* Changes made by cloud service providers as part of their maintenance or updates might be flagged. Verify these changes through official communication from the provider and consider excluding them if they are part of standard operations.

**Response and remediation**

* Immediately isolate the affected EC2 instances by removing them from the compromised security group to prevent further unauthorized access.
* Revert any unauthorized changes to the security group configurations by restoring them to their last known good state using AWS CloudTrail logs for reference.
* Conduct a thorough review of IAM roles and permissions associated with the affected security groups to ensure that only authorized personnel have the ability to modify security group settings.
* Implement additional monitoring and alerting for any future changes to security group configurations, focusing on the specific actions identified in the detection rule.
* Escalate the incident to the security operations team for further investigation and to determine if there are any broader implications or related threats within the AWS environment.
* Review and update the AWS security group policies to enforce stricter rules and minimize the attack surface, ensuring that only necessary ports and protocols are allowed.
* Conduct a post-incident analysis to identify the root cause and implement measures to prevent similar incidents, such as enhancing logging and monitoring capabilities or applying stricter access controls.

**Investigating AWS EC2 Security Group Configuration Change**

This rule identifies any changes to an AWS Security Group, which functions as a virtual firewall controlling inbound and outbound traffic for resources like EC2 instances. Modifications to a security group configuration could expose critical assets to unauthorized access. Threat actors may exploit such changes to establish persistence, exfiltrate data, or pivot within an AWS environment.

**Possible Investigation Steps**

1. ***Identify the Modified Security Group***:

    * ***Security Group ID***: Check the `aws.cloudtrail.flattened.request_parameters.groupId` field to identify the specific security group affected.
    * ***Rule Changes***: Review `aws.cloudtrail.flattened.response_elements.securityGroupRuleSet` to determine the new rules or configurations, including any added or removed IP ranges, protocol changes, and port specifications.

2. ***Review User Context***:

    * ***User Identity***: Inspect the `aws.cloudtrail.user_identity.arn` field to determine which user or role made the modification. Verify if this is an authorized administrator or a potentially compromised account.
    * ***Access Patterns***: Analyze whether this user regularly interacts with security group configurations or if this event is out of the ordinary for their account.

3. ***Analyze the Configuration Change***:

    * ***Egress vs. Ingress***: Determine if the change affected inbound (ingress) or outbound (egress) traffic by reviewing fields like `isEgress` in the `securityGroupRuleSet`. Unauthorized changes to outbound traffic can indicate data exfiltration attempts.
    * ***IP Ranges and Ports***: Assess any added IP ranges, especially `0.0.0.0/0`, which exposes resources to the internet. Port changes should also be evaluated to ensure only necessary ports are open.

4. ***Check User Agent and Source IP***:

    * ***User Agent Analysis***: Examine the `user_agent.original` field to identify the tool or application used, such as `AWS Console` or `Terraform`, which may reveal if the action was automated or manual.
    * ***Source IP and Geolocation***: Use `source.address` and `source.geo` fields to verify if the IP address and geolocation match expected locations for your organization. Unexpected IPs or regions may indicate unauthorized access.

5. ***Evaluate for Persistence Indicators***:

    * ***Repeated Changes***: Investigate if similar changes were recently made across multiple security groups, which may suggest an attempt to maintain or expand access.
    * ***Permissions Review***: Confirm that the user’s IAM policies are configured to limit changes to security groups only as necessary.

6. ***Correlate with Other CloudTrail Events***:

    * ***Cross-Reference Other Security Events***: Look for related actions like `AuthorizeSecurityGroupIngress`, `CreateSecurityGroup`, or `RevokeSecurityGroupIngress` that may indicate additional or preparatory steps for unauthorized access.
    * ***Monitor for IAM or Network Changes***: Check for IAM modifications, network interface changes, or other configuration updates in the same timeframe to detect broader malicious activities.


**False Positive Analysis**

* ***Routine Security Changes***: Security group modifications may be part of regular infrastructure maintenance. Verify if this action aligns with known, scheduled administrative activities.
* ***Automated Configuration Management***: If you are using automated tools like `Terraform` or `CloudFormation`, confirm if the change matches expected configuration drift corrections or deployments.

**Response and Remediation**

* ***Revert Unauthorized Changes***: If unauthorized, revert the security group configuration to its previous state to secure the environment.
* ***Restrict Security Group Permissions***: Remove permissions to modify security groups from any compromised or unnecessary accounts to limit future access.
* ***Quarantine Affected Resources***: If necessary, isolate any affected instances or resources to prevent further unauthorized activity.
* ***Audit IAM and Security Group Policies***: Regularly review permissions related to security groups to ensure least privilege access and prevent excessive access.

**Additional Information**

For more details on managing AWS Security Groups and best practices, refer to the [AWS EC2 Security Groups Documentation](https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2-security-groups.md) and AWS security best practices.


## Rule query [_rule_query_34]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: "ec2.amazonaws.com"
    and event.action:(
            "AuthorizeSecurityGroupEgress" or
            "CreateSecurityGroup" or
            "ModifyInstanceAttribute" or
            "ModifySecurityGroupRules" or
            "RevokeSecurityGroupEgress" or
            "RevokeSecurityGroupIngress")
    and event.outcome: "success"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Cloud Firewall
    * ID: T1562.007
    * Reference URL: [https://attack.mitre.org/techniques/T1562/007/](https://attack.mitre.org/techniques/T1562/007/)




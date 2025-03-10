---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/insecure-aws-ec2-vpc-security-group-ingress-rule-added.html
---

# Insecure AWS EC2 VPC Security Group Ingress Rule Added [insecure-aws-ec2-vpc-security-group-ingress-rule-added]

Identifies when a specified inbound (ingress) rule is added or adjusted for a VPC security group in AWS EC2. This rule detects when a security group rule is added that allows traffic from any IP address or from a specific IP address to common remote access ports, such as 22 (SSH) or 3389 (RDP). Adversaries may add these rules to allow remote access to VPC instances from any location, increasing the attack surface and potentially exposing the instances to unauthorized access.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupEgress.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupEgress.md)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.md)
* [https://www.linkedin.com/pulse/my-backdoors-your-aws-infrastructure-part-3-network-micha%C5%82-brygidyn/](https://www.linkedin.com/pulse/my-backdoors-your-aws-infrastructure-part-3-network-micha%C5%82-brygidyn/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS EC2
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_433]

**Triage and analysis**

**Investigating Insecure AWS EC2 VPC Security Group Ingress Rule Added**

This rule detects the addition of ingress rules to a VPC security group that allow traffic from any IP address (`0.0.0.0/0` or `::/0`) to sensitive ports commonly used for remote access, such as SSH (port 22) and RDP (port 3389). This configuration change can significantly increase the exposure of EC2 instances to potential threats, making it crucial to understand the context and legitimacy of such changes.

**Possible Investigation Steps:**

* ***Identify the Actor***: Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` fields to identify who made the change. Investigate whether this actor has the necessary permissions and typically performs these actions.
* ***Review the Request Details***: Examine the `aws.cloudtrail.request_parameters` to understand exactly what changes were made to the security group. Check for any unusual parameters that could suggest a misconfiguration or malicious intent.
* ***Analyze the Source of the Request***: Look at the `source.ip` and `source.geo` fields to determine the geographical origin of the request. An external or unusual location could indicate compromised credentials.
* ***Contextualize with Timestamp***: Use the `@timestamp` field to check when the change occurred. Modifications outside of typical business hours might warrant additional scrutiny.
* ***Correlate with Other Activities***: Search for related CloudTrail events before and after this change to see if the same actor engaged in other potentially suspicious activities.

**False Positive Analysis:**

* ***Legitimate Administrative Actions***: Verify if the ingress rule change aligns with scheduled updates, maintenance activities, or legitimate administrative tasks documented in change management tickets or systems.
* ***Consistency Check***: Compare the action against historical data of similar actions performed by the user or within the organization. Consistency with past legitimate actions might indicate a false alarm.
* ***Verify through Outcomes***: Check the `aws.cloudtrail.response_elements` and the `event.outcome` to confirm if the change was successful and intended as per policy.

**Response and Remediation:**

* ***Immediate Review and Reversal if Necessary***: If the change was unauthorized, revert the security group rules to their previous state to close any unintended access.
* ***Enhance Monitoring and Alerts***: Adjust monitoring systems to alert on similar security group changes, especially those that open access to well-known ports from any IP address.
* ***Educate and Train***: Provide additional training to users with administrative rights on the importance of security best practices concerning security group management.
* ***Audit Security Groups and Policies***: Conduct a comprehensive audit of all security groups and associated policies to ensure they adhere to the principle of least privilege.
* ***Incident Response***: If there’s an indication of malicious intent or a security breach, initiate the incident response protocol to mitigate any damage and prevent future occurrences.

**Additional Information:**

For further guidance on managing security group rules and securing AWS environments, refer to the [Amazon VPC Security Groups documentation](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.md) and AWS best practices for security.


## Rule query [_rule_query_467]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: ec2.amazonaws.com
    and event.action: AuthorizeSecurityGroupIngress
    and event.outcome: success
    and aws.cloudtrail.flattened.request_parameters.cidrIp: ("0.0.0.0/0" or "::/0")
    and aws.cloudtrail.flattened.request_parameters.fromPort: (
        21 or 22 or 23 or 445 or 3389 or 5985 or 5986)
```

**Framework**: MITRE ATT&CKTM

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




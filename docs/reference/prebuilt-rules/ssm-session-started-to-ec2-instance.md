---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/ssm-session-started-to-ec2-instance.html
---

# SSM Session Started to EC2 Instance [ssm-session-started-to-ec2-instance]

Identifies the first occurrence of an AWS resource establishing a session via SSM to an EC2 instance. Adversaries may use AWS Systems Manager to establish a session to an EC2 instance to execute commands on the instance. This can be used to gain access to the instance and perform actions such as privilege escalation. This rule helps detect the first occurrence of this activity for a given AWS resource.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_StartSession.html](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_StartSession.md)
* [https://hackingthe.cloud/aws/post_exploitation/intercept_ssm_communications/](https://hackingthe.cloud/aws/post_exploitation/intercept_ssm_communications/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS SSM
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_899]

**Triage and analysis**

**Investigating SSM Session Started to EC2 Instance**

This rule detects the first instance of an AWS resource initiating an SSM session to an EC2 instance, which could be indicative of legitimate administrative activities or potential malicious actions like command execution or lateral movement.

**Possible Investigation Steps**

* ***Examine the Session Start Event***: Review the AWS CloudTrail log for the event.
* Look for the `StartSession` action and verify details such as the `user_identity.arn`, `event.action`, and the target EC2 instance (`aws.cloudtrail.flattened.request_parameters`).
* ***Verify User Identity and Role***: Check the user’s ARN and access key ID (`aws.cloudtrail.user_identity.access_key_id`).
* Cross-reference this with IAM to verify if the user had the necessary permissions and if their role typically requires initiating SSM sessions.
* ***Assess Geographic and IP Context***: Analyze the source IP (`source.ip`) and geographic location (`source.geo`) from which the session was initiated.
* Determine if these are consistent with typical user locations or if they raise suspicions of compromise or misuse.
* ***Review Session Details***: Examine details like the session ID and stream URL (`aws.cloudtrail.flattened.response_elements`) to understand the scope and nature of the session.
* Check if any commands executed during the session were unauthorized or out of ordinary practices.
* ***Correlate with Other Security Events***: Look for other related security events around the time of the session start to identify any pattern or broader attack vector that may involve this user or EC2 instance.

**False Positive Analysis**

* ***Legitimate Administrative Activities***: Confirm whether the SSM session was initiated for valid administrative purposes such as system maintenance, patching, or configuration updates. Verify with the respective teams or personnel.

**Response and Remediation**

* ***Immediate Session Review***: If the session initiation seems suspicious, review all actions taken during the session.
* If possible, terminate the session to prevent any potential harm.
* ***Validate and Reinforce Security Policies***: Ensure that policies around SSM session initiation are strict and adhere to the principle of least privilege.
* Update IAM policies if necessary to tighten controls.
* ***Incident Response Activation***: If malicious intent or actions are confirmed, activate the incident response protocol.
* This includes containment of the threat, eradication of the adversary’s presence, recovery of affected systems, and a thorough investigation.
* ***Enhance Monitoring and Alerts***: Improve monitoring of SSM sessions, particularly focusing on sessions that involve sensitive or critical EC2 instances.
* Adjust alerting mechanisms to flag unusual session initiations promptly.

**Additional Information**

For more in-depth understanding of managing SSM sessions and security best practices, refer to the [AWS Systems Manager documentation](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_StartSession.md). Additionally, consider the security implications and best practices outlined in [AWS SSM privilege escalation techniques](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-ssm-privesc).


## Rule query [_rule_query_955]

```js
event.dataset:"aws.cloudtrail" and event.provider:"ssm.amazonaws.com"
    and event.action:"StartSession" and event.outcome:"success"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: Cloud Services
    * ID: T1021.007
    * Reference URL: [https://attack.mitre.org/techniques/T1021/007/](https://attack.mitre.org/techniques/T1021/007/)




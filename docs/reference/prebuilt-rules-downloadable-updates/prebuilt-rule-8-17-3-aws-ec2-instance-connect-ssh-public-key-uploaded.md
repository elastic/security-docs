---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-aws-ec2-instance-connect-ssh-public-key-uploaded.html
---

# AWS EC2 Instance Connect SSH Public Key Uploaded [prebuilt-rule-8-17-3-aws-ec2-instance-connect-ssh-public-key-uploaded]

Identifies when a new SSH public key is uploaded to an AWS EC2 instance using the EC2 Instance Connect service. This action could indicate an adversary attempting to maintain access to the instance. The rule also detects the `SendSerialConsoleSSHPublicKey` or `SendSSHPublicKey` API actions, which are logged when manually uploading an SSH key to an EC2 instance or serial connection. It is important to know that this API call happens automatically by the EC2 Instance Connect service when a user connects to an EC2 instance using the EC2 Instance Connect service via the CLI or AWS Management Console.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://stratus-red-team.cloud/attack-techniques/AWS/aws.lateral-movement.ec2-instance-connect/](https://stratus-red-team.cloud/attack-techniques/AWS/aws.lateral-movement.ec2-instance-connect/)
* [https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-ec2-privesc](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-ec2-privesc)
* [https://medium.parttimepolymath.net/aws-ec2-instance-connect-a-very-neat-trick-4d2fc0c28010](https://medium.parttimepolymath.net/aws-ec2-instance-connect-a-very-neat-trick-4d2fc0c28010)
* [https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSSHPublicKey.html](https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSSHPublicKey.md)
* [https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSerialConsoleSSHPublicKey.html](https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSerialConsoleSSHPublicKey.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS EC2
* Use Case: Identity and Access Audit
* Tactic: Privilege Escalation
* Tactic: Lateral Movement

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3916]

**Triage and Analysis**

**Investigating AWS EC2 Instance Connect SSH Public Key Uploaded**

This rule detects when a new SSH public key is uploaded to an AWS EC2 instance using the EC2 Instance Connect service. Adversaries may upload SSH public keys to EC2 instances to maintain access to the instance or for initial access. This action also occurs automatically in the background when establishing a connection to an instance via the same service.  The rule also covers cases where the `SendSerialConsoleSSHPublicKey` API action is used to upload an SSH public key to a serial connection, which can be exploited for privilege escalation.

**Possible Investigation Steps:**

* ***Identify the Actor***: Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` fields to identify who performed the action. Verify if this actor typically performs such actions and if they have the necessary permissions.
* ***Review the Request Details***: Examine the `aws.cloudtrail.request_parameters` to understand the specific details of the SSH public key upload. Look for any unusual parameters that could suggest unauthorized or malicious modifications.
* ***Analyze the Source of the Request***: Investigate the `source.ip` and `source.geo` fields to determine the geographical origin of the request. An external or unexpected location might indicate compromised credentials or unauthorized access.
* ***Contextualize with Timestamp***: Use the `@timestamp` field to check when the SSH public key was uploaded. Changes during non-business hours or outside regular maintenance windows might require further scrutiny.
* ***Correlate with Other Activities***: Search for related CloudTrail events before and after this action to see if the same actor or IP address engaged in other potentially suspicious activities.
* ***Check for Serial Console Access***: If the `SendSerialConsoleSSHPublicKey` action was used, verify if the `ec2:EnableSerialConsoleAccess` permission was also used, which might indicate an attempt to enable and exploit the serial console.

**False Positive Analysis:**

* ***Legitimate Administrative Actions***: Confirm if the SSH public key upload aligns with scheduled updates, development activities, or legitimate administrative tasks documented in change management systems.
* ***Consistency Check***: Compare the action against historical data of similar actions performed by the user or within the organization. If the action is consistent with past legitimate activities, it might indicate a false alarm.
* ***Verify through Outcomes***: Check the `aws.cloudtrail.response_elements` and the `event.outcome` to confirm if the upload was successful and intended according to policy.

**Response and Remediation:**

* ***Immediate Review and Reversal if Necessary***: If the upload was unauthorized, remove the uploaded SSH public key from the EC2 instance and review the instance’s access logs for any suspicious activity.
* ***Enhance Monitoring and Alerts***: Adjust monitoring systems to alert on similar actions, especially those involving sensitive instances or unusual file extensions.
* ***Educate and Train***: Provide additional training to users with administrative rights on the importance of security best practices concerning SSH key management and the risks of unauthorized key uploads.
* ***Audit EC2 Instance Policies and Permissions***: Conduct a comprehensive audit of all EC2 instance policies and associated permissions to ensure they adhere to the principle of least privilege.
* ***Incident Response***: If there’s an indication of malicious intent or a security breach, initiate the incident response protocol to mitigate any damage and prevent future occurrences.

**Additional Information:**

For further guidance on managing EC2 instances and securing AWS environments, refer to the [AWS EC2 Instance Connect documentation](https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSSHPublicKey.md) and AWS best practices for security. Additionally, consult the following resources for specific details on SSH key management and privilege escalation techniques: - [Stratus Red Team - AWS EC2 Instance Connect](https://stratus-red-team.cloud/attack-techniques/AWS/aws.lateral-movement.ec2-instance-connect/) - [HackTricks - AWS EC2 Privilege Escalation](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-ec2-privesc) - [AWS EC2 Instance Connect API Reference](https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSSHPublicKey.md)


## Rule query [_rule_query_4849]

```js
event.dataset: aws.cloudtrail
    and event.provider: ec2-instance-connect.amazonaws.com
    and event.action: (SendSSHPublicKey or SendSerialConsoleSSHPublicKey)
    and event.outcome: success
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

    * Name: SSH
    * ID: T1021.004
    * Reference URL: [https://attack.mitre.org/techniques/T1021/004/](https://attack.mitre.org/techniques/T1021/004/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Sub-technique:

    * Name: SSH Authorized Keys
    * ID: T1098.004
    * Reference URL: [https://attack.mitre.org/techniques/T1098/004/](https://attack.mitre.org/techniques/T1098/004/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-ec2-instance-console-login-via-assumed-role.html
---

# AWS EC2 Instance Console Login via Assumed Role [prebuilt-rule-8-17-4-aws-ec2-instance-console-login-via-assumed-role]

Identifies a successful console login activity by an EC2 instance profile using an assumed role. This is uncommon behavior and could indicate an attacker using compromised credentials to further exploit an environment. An EC2 instance assumes a role using their EC2 ID as the session name. This rule looks for the pattern "i-" which is the beginning pattern for assumed role sessions started by an EC2 instance and a successful `ConsoleLogin` or `GetSigninToken` API call.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://redcanary.com/blog/aws-sts/](https://redcanary.com/blog/aws-sts/)
* [https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html/](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.md/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS EC2
* Data Source: AWS STS
* Use Case: Identity and Access Audit
* Tactic: Lateral Movement
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4037]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS EC2 Instance Console Login via Assumed Role**

AWS EC2 instances can assume roles to access resources securely, using temporary credentials. This mechanism, while essential for legitimate operations, can be exploited by adversaries who gain access to EC2 credentials, allowing them to assume roles and perform unauthorized actions. The detection rule identifies unusual console login activities by EC2 instances, flagging potential misuse by checking for specific session patterns and successful login events, thus helping to uncover lateral movement or credential access attempts.

**Possible investigation steps**

* Review the CloudTrail logs for the specific event where event.dataset is "aws.cloudtrail" and event.provider is "signin.amazonaws.com" to gather more details about the login event.
* Identify the EC2 instance associated with the session by examining the user.id field for the pattern ":i-" and correlate it with known EC2 instance IDs in your environment.
* Check the AWS CloudTrail logs for any other activities performed by the same assumed role session to identify any unauthorized actions or lateral movement attempts.
* Investigate the source IP address and geolocation of the login event to determine if it aligns with expected access patterns for your organization.
* Verify the IAM role policies and permissions associated with the assumed role to assess the potential impact of the unauthorized access.
* Review recent changes to the IAM roles and policies to identify any unauthorized modifications that could have facilitated the assumed role access.
* Contact the instance owner or relevant team to confirm if the login activity was expected or authorized, and take appropriate action if it was not.

**False positive analysis**

* Routine administrative tasks: EC2 instances may assume roles for legitimate administrative purposes, such as automated deployments or maintenance tasks. To manage this, identify and whitelist known administrative session patterns or specific instance IDs that regularly perform these tasks.
* Monitoring and logging services: Some monitoring or logging services might use assumed roles to access AWS resources for data collection. Review and exclude these services by identifying their specific session patterns or instance IDs.
* Scheduled jobs or scripts: Automated scripts or scheduled jobs running on EC2 instances might assume roles for resource access. Document these jobs and create exceptions for their session patterns to prevent false alerts.
* Development and testing environments: Instances in development or testing environments might frequently assume roles for testing purposes. Consider excluding these environments from the rule or creating specific exceptions for known testing activities.
* Third-party integrations: Some third-party tools or integrations might require EC2 instances to assume roles for functionality. Verify these integrations and exclude their session patterns or instance IDs from triggering alerts.

**Response and remediation**

* Immediately revoke the temporary credentials associated with the compromised EC2 instance to prevent further unauthorized access.
* Isolate the affected EC2 instance from the network to contain any potential lateral movement by the attacker.
* Conduct a thorough review of CloudTrail logs to identify any unauthorized actions performed using the assumed role and assess the extent of the compromise.
* Reset and rotate all credentials and access keys associated with the compromised EC2 instance and any other potentially affected resources.
* Implement stricter IAM policies and role permissions to limit the scope of access for EC2 instances, ensuring the principle of least privilege is enforced.
* Notify the security operations team and relevant stakeholders about the incident for further investigation and to initiate any necessary legal or compliance procedures.
* Enhance monitoring and alerting mechanisms to detect similar patterns of unusual console login activities in the future, ensuring rapid response to potential threats.


## Rule query [_rule_query_5054]

```js
any where event.dataset == "aws.cloudtrail"
   and event.provider == "signin.amazonaws.com"
   and event.action in ("ConsoleLogin", "GetSigninToken")
   and event.outcome == "success"
   and aws.cloudtrail.user_identity.type == "AssumedRole"
   and stringContains (user.id, ":i-")
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

* Technique:

    * Name: Use Alternate Authentication Material
    * ID: T1550
    * Reference URL: [https://attack.mitre.org/techniques/T1550/](https://attack.mitre.org/techniques/T1550/)

* Sub-technique:

    * Name: Application Access Token
    * ID: T1550.001
    * Reference URL: [https://attack.mitre.org/techniques/T1550/001/](https://attack.mitre.org/techniques/T1550/001/)

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-ec2-instance-interaction-with-iam-service.html
---

# AWS EC2 Instance Interaction with IAM Service [aws-ec2-instance-interaction-with-iam-service]

Identifies when an EC2 instance interacts with the AWS IAM service via an assumed role. This is uncommon behavior and could indicate an attacker using compromised credentials to further exploit an environment. For example, an assumed role could be used to create new users for persistence or add permissions for privilege escalation. An EC2 instance assumes a role using their EC2 ID as the session name. This rule looks for the pattern "i-" which is the beginning pattern for assumed role sessions started by an EC2 instance. This is a [building block](docs-content://solutions/security/detect-and-alert/about-building-block-rules.md) rule and does not generate alerts on its own. It is meant to be used for correlation with other rules to detect suspicious activity.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://redcanary.com/blog/aws-sts/](https://redcanary.com/blog/aws-sts/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS EC2
* Data Source: AWS IAM
* Use Case: Identity and Access Audit
* Tactic: Privilege Escalation
* Tactic: Persistence
* Rule Type: BBR

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_29]

```js
any where event.dataset == "aws.cloudtrail"
    and event.provider == "iam.amazonaws.com"
    and aws.cloudtrail.user_identity.type == "AssumedRole"
    and stringContains(user.id, ":i-")
    and (
            startsWith(event.action, "Update")
            or startsWith(event.action, "Attach")
            or startsWith(event.action, "Detach")
            or startsWith(event.action, "Create")
            or startsWith(event.action, "Delete")
            or startsWith(event.action, "Add")
            or startsWith(event.action, "Remove")
            or startsWith(event.action, "Put")
            or startsWith(event.action, "Tag")
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Cloud Accounts
    * ID: T1078.004
    * Reference URL: [https://attack.mitre.org/techniques/T1078/004/](https://attack.mitre.org/techniques/T1078/004/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Sub-technique:

    * Name: Additional Cloud Credentials
    * ID: T1098.001
    * Reference URL: [https://attack.mitre.org/techniques/T1098/001/](https://attack.mitre.org/techniques/T1098/001/)

* Sub-technique:

    * Name: Additional Cloud Roles
    * ID: T1098.003
    * Reference URL: [https://attack.mitre.org/techniques/T1098/003/](https://attack.mitre.org/techniques/T1098/003/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)




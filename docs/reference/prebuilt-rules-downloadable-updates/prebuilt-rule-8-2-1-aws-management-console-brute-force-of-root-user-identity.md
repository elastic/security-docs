---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-management-console-brute-force-of-root-user-identity.html
---

# AWS Management Console Brute Force of Root User Identity [prebuilt-rule-8-2-1-aws-management-console-brute-force-of-root-user-identity]

Identifies a high number of failed authentication attempts to the AWS management console for the Root user identity. An adversary may attempt to brute force the password for the Root user identity, as it has complete access to all services and resources for the AWS account.

**Rule type**: threshold

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-20m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Identity and Access

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1832]



## Rule query [_rule_query_2122]

```js
event.dataset:aws.cloudtrail and event.provider:signin.amazonaws.com and event.action:ConsoleLogin and aws.cloudtrail.user_identity.type:Root and event.outcome:failure
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Brute Force
    * ID: T1110
    * Reference URL: [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)




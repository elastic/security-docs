---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-sts-getsessiontoken-abuse.html
---

# AWS STS GetSessionToken Abuse [prebuilt-rule-8-2-1-aws-sts-getsessiontoken-abuse]

Identifies the suspicious use of GetSessionToken. Tokens could be created and used by attackers to move laterally and escalate privileges.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Identity and Access

**Version**: 3

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1886]



## Rule query [_rule_query_2171]

```js
event.dataset:aws.cloudtrail and event.provider:sts.amazonaws.com and event.action:GetSessionToken and
aws.cloudtrail.user_identity.type:IAMUser and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Use Alternate Authentication Material
    * ID: T1550
    * Reference URL: [https://attack.mitre.org/techniques/T1550/](https://attack.mitre.org/techniques/T1550/)

* Sub-technique:

    * Name: Application Access Token
    * ID: T1550.001
    * Reference URL: [https://attack.mitre.org/techniques/T1550/001/](https://attack.mitre.org/techniques/T1550/001/)




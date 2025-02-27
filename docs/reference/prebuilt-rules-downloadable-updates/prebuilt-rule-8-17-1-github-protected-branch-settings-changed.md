---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-1-github-protected-branch-settings-changed.html
---

# GitHub Protected Branch Settings Changed [prebuilt-rule-8-17-1-github-protected-branch-settings-changed]

This rule detects setting modifications for protected branches of a GitHub repository. Branch protection rules can be used to enforce certain workflows or requirements before a contributor can push changes to a branch in your repository. Changes to these protected branch settings should be investigated and verified as legitimate activity. Unauthorized changes could be used to lower your organization’s security posture and leave you exposed for future attacks.

**Rule type**: eql

**Rule indices**:

* logs-github.audit-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Cloud
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Github

**Version**: 206

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4786]

```js
configuration where event.dataset == "github.audit"
  and github.category == "protected_branch" and event.type == "change"
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

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)




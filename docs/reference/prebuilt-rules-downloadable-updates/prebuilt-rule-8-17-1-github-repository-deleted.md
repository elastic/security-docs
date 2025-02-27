---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-1-github-repository-deleted.html
---

# GitHub Repository Deleted [prebuilt-rule-8-17-1-github-repository-deleted]

This rule detects when a GitHub repository is deleted within your organization. Repositories are a critical component used within an organization to manage work, collaborate with others and release products to the public. Any delete action against a repository should be investigated to determine it’s validity. Unauthorized deletion of organization repositories could cause irreversible loss of intellectual property and indicate compromise within your organization.

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
* Use Case: UEBA
* Tactic: Impact
* Data Source: Github

**Version**: 203

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4788]

```js
configuration where event.module == "github" and event.dataset == "github.audit" and event.action == "repo.destroy"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Destruction
    * ID: T1485
    * Reference URL: [https://attack.mitre.org/techniques/T1485/](https://attack.mitre.org/techniques/T1485/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/github-app-deleted.html
---

# GitHub App Deleted [github-app-deleted]

Detects the deletion of a GitHub app either from a repo or an organization.

**Rule type**: eql

**Rule indices**:

* logs-github.audit-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Cloud
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Github
* Resources: Investigation Guide

**Version**: 205

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_382]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GitHub App Deleted**

GitHub Apps are integrations that extend GitHub’s functionality, often used to automate workflows or manage repositories. Adversaries might delete these apps to disrupt operations or remove security controls. The detection rule monitors audit logs for app deletions, flagging potential unauthorized actions. By focusing on specific event types and categories, it helps identify suspicious deletions that could indicate malicious activity.

**Possible investigation steps**

* Review the audit logs for the specific event type "deletion" within the "integration_installation" category to identify the exact GitHub app that was deleted.
* Determine the user or account responsible for the deletion by examining the associated user information in the audit logs.
* Check the timing of the deletion event to see if it coincides with any other suspicious activities or anomalies in the repository or organization.
* Investigate the role and permissions of the user who performed the deletion to assess if they had legitimate access and authorization to delete the app.
* Look into the history of the deleted GitHub app to understand its purpose, usage, and any dependencies it might have had within the organization or repository.
* Communicate with the team or organization members to verify if the deletion was intentional and authorized, or if it was unexpected and potentially malicious.

**False positive analysis**

* Routine maintenance or updates by authorized personnel can trigger app deletions. Verify with the team responsible for GitHub app management to confirm if the deletion was planned.
* Automated scripts or tools used for managing GitHub apps might inadvertently delete apps during updates or reconfigurations. Review the scripts and ensure they have proper safeguards to prevent accidental deletions.
* Organizational policy changes might lead to the removal of certain apps. Check if there have been recent policy updates that could explain the deletion.
* Exclude specific users or service accounts known to perform legitimate app deletions regularly by creating exceptions in the detection rule.
* Monitor for patterns of deletions that align with scheduled maintenance windows and adjust the rule to ignore these timeframes if they consistently result in false positives.

**Response and remediation**

* Immediately revoke any compromised credentials or tokens associated with the deleted GitHub app to prevent unauthorized access.
* Restore the deleted GitHub app from a backup or re-install it to ensure continuity of operations and security controls.
* Conduct a thorough review of recent changes and activities in the affected repositories or organization to identify any unauthorized actions or data alterations.
* Notify the security team and relevant stakeholders about the incident to ensure awareness and coordinated response efforts.
* Implement additional monitoring on the affected repositories or organization to detect any further suspicious activities or attempts to delete apps.
* Review and tighten permissions for GitHub apps to ensure only authorized personnel have the ability to delete or modify app installations.
* Escalate the incident to higher-level security management if there is evidence of a broader compromise or if the deletion is part of a larger attack campaign.


## Rule query [_rule_query_414]

```js
configuration where event.dataset == "github.audit" and github.category == "integration_installation" and event.type == "deletion"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Serverless Execution
    * ID: T1648
    * Reference URL: [https://attack.mitre.org/techniques/T1648/](https://attack.mitre.org/techniques/T1648/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-github-protected-branch-settings-changed.html
---

# GitHub Protected Branch Settings Changed [prebuilt-rule-8-17-4-github-protected-branch-settings-changed]

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
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4181]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GitHub Protected Branch Settings Changed**

GitHub’s protected branch settings are crucial for maintaining code integrity by enforcing rules like requiring reviews before merging. Adversaries may alter these settings to bypass security measures, facilitating unauthorized code changes. The detection rule monitors audit logs for changes in branch protection, flagging potential defense evasion attempts for further investigation.

**Possible investigation steps**

* Review the GitHub audit logs to identify the specific changes made to the protected branch settings, focusing on entries where event.dataset is "github.audit" and github.category is "protected_branch".
* Determine the user account responsible for the changes by examining the audit log details, and verify if the account has a legitimate reason to modify branch protection settings.
* Check the timing of the changes to see if they coincide with any other suspicious activities or known incidents within the organization.
* Investigate the context of the change by reviewing recent pull requests or commits to the affected branch to assess if the changes align with ongoing development activities.
* Communicate with the repository owner or relevant team members to confirm if the changes were authorized and necessary for current project requirements.
* Evaluate the impact of the changes on the repository’s security posture and consider reverting the changes if they were unauthorized or pose a security risk.

**False positive analysis**

* Routine updates by trusted team members may trigger alerts. To manage this, create exceptions for specific users or teams who regularly update branch protection settings as part of their role.
* Automated tools or scripts that modify branch settings for legitimate reasons can cause false positives. Identify these tools and whitelist their activities in the monitoring system.
* Scheduled maintenance or policy updates might lead to expected changes in branch protection settings. Document these events and adjust the detection rule to ignore changes during these periods.
* Changes made by administrators during onboarding or offboarding processes can be mistaken for unauthorized activity. Ensure these processes are well-documented and communicated to the security team to prevent unnecessary alerts.

**Response and remediation**

* Immediately revert any unauthorized changes to the protected branch settings to restore the original security posture.
* Conduct a review of recent commits and merges to the affected branch to identify any unauthorized code changes that may have occurred during the period of altered settings.
* Temporarily restrict access to the repository for users who made unauthorized changes until a full investigation is completed.
* Notify the security team and relevant stakeholders about the incident for further analysis and to determine if additional security measures are needed.
* Implement additional monitoring on the affected repository to detect any further unauthorized changes or suspicious activities.
* Review and update access controls and permissions for the repository to ensure that only authorized personnel can modify branch protection settings.
* Document the incident, including the timeline of events and actions taken, to improve future response efforts and update incident response plans.


## Rule query [_rule_query_5190]

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




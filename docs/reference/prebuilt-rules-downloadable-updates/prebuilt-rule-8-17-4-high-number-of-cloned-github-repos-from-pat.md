---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-high-number-of-cloned-github-repos-from-pat.html
---

# High Number of Cloned GitHub Repos From PAT [prebuilt-rule-8-17-4-high-number-of-cloned-github-repos-from-pat]

Detects a high number of unique private repo clone events originating from a single personal access token within a short time period.

**Rule type**: threshold

**Rule indices**:

* logs-github.audit-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Cloud
* Use Case: Threat Detection
* Use Case: UEBA
* Tactic: Execution
* Data Source: Github
* Resources: Investigation Guide

**Version**: 205

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4183]

**Triage and analysis**

[TBC: QUOTE]
**Investigating High Number of Cloned GitHub Repos From PAT**

Personal Access Tokens (PATs) facilitate automated access to GitHub repositories, enabling seamless integration and management. However, adversaries can exploit compromised PATs to clone numerous private repositories rapidly, potentially exfiltrating sensitive code. The detection rule identifies unusual cloning activity by monitoring for a surge in unique private repo clones from a single PAT, signaling potential misuse.

**Possible investigation steps**

* Review the specific personal access token (PAT) involved in the alert to determine its owner and associated user account.
* Analyze the event logs for the PAT to identify the number and names of private repositories cloned, focusing on any unusual or unauthorized access patterns.
* Check the access history of the PAT to see if there are any other suspicious activities or anomalies, such as access from unfamiliar IP addresses or locations.
* Contact the owner of the PAT to verify if the cloning activity was authorized and to gather additional context about the usage of the token.
* Investigate the security posture of the affected repositories, including reviewing access permissions and recent changes to repository settings.
* Consider revoking the compromised PAT and issuing a new one if unauthorized access is confirmed, and ensure the user updates any systems or scripts using the old token.

**False positive analysis**

* Legitimate automated processes or CI/CD pipelines may trigger multiple clone events. Review and whitelist known IP addresses or tokens associated with these processes to prevent false alerts.
* Developers working on multiple projects might clone several private repositories in a short period. Identify and exclude these users or their tokens from triggering alerts by maintaining a list of frequent cloners.
* Organizational scripts or tools that require cloning multiple repositories for updates or backups can cause false positives. Document these scripts and create exceptions for their associated tokens.
* Scheduled maintenance or migration activities involving repository cloning can be mistaken for suspicious activity. Coordinate with relevant teams to anticipate such events and temporarily adjust detection thresholds or exclude specific tokens.

**Response and remediation**

* Immediately revoke the compromised Personal Access Token (PAT) to prevent further unauthorized access to private repositories.
* Notify the repository owners and relevant stakeholders about the potential breach to assess the impact and initiate internal incident response procedures.
* Conduct a thorough review of the cloned repositories to identify any sensitive or proprietary information that may have been exposed.
* Implement additional access controls, such as IP whitelisting or two-factor authentication, to enhance security for accessing private repositories.
* Monitor for any unusual activity or further unauthorized access attempts using other PATs or credentials.
* Escalate the incident to the security team for a comprehensive investigation and to determine if any other systems or data have been compromised.
* Update and enforce policies regarding the creation, usage, and management of PATs to prevent similar incidents in the future.


## Rule query [_rule_query_5192]

```js
event.dataset:"github.audit" and event.category:"configuration" and event.action:"git.clone" and
github.programmatic_access_type:("OAuth access token" or "Fine-grained personal access token") and
github.repository_public:false
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




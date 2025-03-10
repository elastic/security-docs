---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/azure-entra-sign-in-brute-force-microsoft-365-accounts-by-repeat-source.html
---

# Azure Entra Sign-in Brute Force Microsoft 365 Accounts by Repeat Source [azure-entra-sign-in-brute-force-microsoft-365-accounts-by-repeat-source]

Identifies potential brute-force attempts against Microsoft 365 user accounts by detecting a high number of failed interactive or non-interactive login attempts within a 30-minute window from a single source. Attackers may attempt to brute force user accounts to gain unauthorized access to Microsoft 365 services via different services such as Exchange, SharePoint, or Teams.

**Rule type**: esql

**Rule indices**: None

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-unauthenticated-enum-and-initial-entry/az-password-spraying](https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-unauthenticated-enum-and-initial-entry/az-password-spraying)
* [https://github.com/0xZDH/o365spray](https://github.com/0xZDH/o365spray)

**Tags**:

* Domain: Cloud
* Domain: SaaS
* Data Source: Azure
* Data Source: Entra ID
* Data Source: Entra ID Sign-in
* Use Case: Identity and Access Audit
* Use Case: Threat Detection
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_188]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Entra Sign-in Brute Force Microsoft 365 Accounts by Repeat Source**

Azure Entra ID, integral to Microsoft 365, manages identity and access, ensuring secure authentication. Adversaries exploit this by attempting numerous failed logins to breach accounts. The detection rule identifies such brute-force attempts by monitoring failed logins from a single IP within a short timeframe, flagging potential unauthorized access efforts.

**Possible investigation steps**

* Review the source IP address identified in the alert to determine if it is associated with known malicious activity or if it belongs to a legitimate user or organization.
* Examine the list of user principal names targeted by the failed login attempts to identify any patterns or specific users that may be at higher risk.
* Check the azure.signinlogs.properties.resource_display_name to understand which Microsoft 365 services were targeted, such as Exchange, SharePoint, or Teams, and assess the potential impact on those services.
* Investigate the error codes in azure.signinlogs.properties.status.error_code for additional context on why the login attempts failed, which may provide insights into the attacker’s methods.
* Correlate the failed login attempts with any successful logins from the same source IP or user accounts to identify potential unauthorized access.
* Assess the risk and exposure of the affected user accounts and consider implementing additional security measures, such as multi-factor authentication, if not already in place.

**False positive analysis**

* High volume of legitimate login attempts from a single IP, such as a corporate proxy or VPN, can trigger false positives. To mitigate, exclude known IP addresses of trusted network infrastructure from the rule.
* Automated scripts or applications performing frequent login operations on behalf of users may be misidentified as brute force attempts. Identify and whitelist these applications by their source IPs or user agents.
* Shared workstations or kiosks where multiple users log in from the same IP address can result in false positives. Implement user-based exclusions for these environments to prevent unnecessary alerts.
* Frequent password resets or account recovery processes can generate multiple failed login attempts. Monitor and exclude these activities by correlating with password reset logs or helpdesk tickets.
* Training or testing environments where multiple failed logins are expected should be excluded by identifying and filtering out the associated IP ranges or user accounts.

**Response and remediation**

* Immediately block the source IP address identified in the alert to prevent further unauthorized access attempts.
* Reset passwords for all affected user accounts that experienced failed login attempts from the flagged IP address to ensure account security.
* Enable multi-factor authentication (MFA) for the affected accounts if not already in place, to add an additional layer of security against unauthorized access.
* Review and update conditional access policies to restrict access from suspicious or untrusted locations, enhancing security posture.
* Notify the security operations team and relevant stakeholders about the incident for awareness and further investigation.
* Monitor the affected accounts and source IP for any additional suspicious activity, ensuring no further attempts are made.
* Document the incident details, including the source IP, affected accounts, and actions taken, for future reference and compliance purposes.

This rule relies on Azure Entra ID sign-in logs, but filters for Microsoft 365 resources.


## Rule query [_rule_query_193]

```js
from logs-azure.signinlogs*
| WHERE
  event.dataset == "azure.signinlogs"
  and event.category == "authentication"
  and to_lower(azure.signinlogs.properties.resource_display_name) rlike "(.*)365(.*)"
  and azure.signinlogs.category in ("NonInteractiveUserSignInLogs", "SignInLogs")
  and event.outcome != "success"

  // For tuning, review azure.signinlogs.properties.status.error_code
  // https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes

// keep only relevant fields
| keep event.dataset, event.category, azure.signinlogs.properties.resource_display_name, azure.signinlogs.category, event.outcome, azure.signinlogs.properties.user_principal_name, source.ip

// Count the number of unique targets per source IP
| stats
  target_count = count_distinct(azure.signinlogs.properties.user_principal_name) by source.ip

// Filter for at least 10 distinct failed login attempts from a single source
| where target_count >= 10
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




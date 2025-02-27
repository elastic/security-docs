---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-azure-entra-sign-in-brute-force-against-microsoft-365-accounts.html
---

# Azure Entra Sign-in Brute Force against Microsoft 365 Accounts [prebuilt-rule-8-17-4-azure-entra-sign-in-brute-force-against-microsoft-365-accounts]

Identifies potential brute-force attempts against Microsoft 365 user accounts by detecting a high number of failed interactive or non-interactive login attempts within a 30-minute window. Attackers may attempt to brute force user accounts to gain unauthorized access to Microsoft 365 services via different services such as Exchange, SharePoint, or Teams.

**Rule type**: esql

**Rule indices**: None

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

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

## Investigation guide [_investigation_guide_4084]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Entra Sign-in Brute Force against Microsoft 365 Accounts**

Azure Entra ID, integral to Microsoft 365, manages user identities and access. Adversaries exploit this by attempting numerous login attempts to breach accounts, targeting services like Exchange and Teams. The detection rule identifies such threats by analyzing failed login patterns within a 30-minute window, flagging unusual activity from multiple sources or excessive failed attempts, thus highlighting potential brute-force attacks.

**Possible investigation steps**

* Review the `azure.signinlogs.properties.user_principal_name` to identify the specific user account targeted by the brute-force attempts.
* Examine the `source.ip` field to determine the origin of the failed login attempts and assess if multiple IP addresses are involved, indicating a distributed attack.
* Check the `azure.signinlogs.properties.resource_display_name` to understand which Microsoft 365 services (e.g., Exchange, SharePoint, Teams) were targeted during the login attempts.
* Analyze the `target_time_window` to confirm the timeframe of the attack and correlate it with other security events or alerts that may have occurred simultaneously.
* Investigate the `azure.signinlogs.properties.status.error_code` for specific error codes that might provide additional context on the nature of the failed login attempts.
* Assess the user’s recent activity and any changes in behavior or access patterns that could indicate a compromised account or insider threat.

**False positive analysis**

* High volume of legitimate login attempts from a single user can trigger false positives, especially during password resets or account recovery processes. To mitigate this, consider excluding known IP addresses associated with IT support or helpdesk operations.
* Automated scripts or applications that frequently access Microsoft 365 services using non-interactive logins may be misidentified as brute force attempts. Identify and whitelist these applications by their user principal names or IP addresses.
* Users traveling or working remotely may log in from multiple locations in a short period, leading to false positives. Implement geolocation-based exclusions for known travel patterns or use conditional access policies to manage these scenarios.
* Bulk operations performed by administrators, such as batch account updates or migrations, can result in numerous failed logins. Exclude these activities by recognizing the specific user principal names or IP addresses involved in such operations.
* Frequent logins from shared IP addresses, such as those from corporate VPNs or proxy servers, might be flagged. Consider excluding these IP ranges if they are known and trusted within the organization.

**Response and remediation**

* Immediately isolate the affected user accounts by disabling them to prevent further unauthorized access.
* Conduct a password reset for the compromised accounts, ensuring the new passwords are strong and unique.
* Review and block the IP addresses associated with the failed login attempts to prevent further access attempts from these sources.
* Enable multi-factor authentication (MFA) for the affected accounts and any other accounts that do not have it enabled to add an additional layer of security.
* Monitor the affected accounts and related services for any unusual activity or signs of compromise post-remediation.
* Escalate the incident to the security operations team for further investigation and to determine if there are broader implications or related threats.
* Update and enhance detection rules and monitoring to identify similar brute-force attempts in the future, ensuring quick response to any new threats.

This rule relies on Azure Entra ID sign-in logs, but filters for Microsoft 365 resources.


## Rule query [_rule_query_5101]

```js
from logs-azure.signinlogs*
// truncate the timestamp to a 30-minute window
| eval target_time_window = DATE_TRUNC(30 minutes, @timestamp)
| WHERE
  event.dataset == "azure.signinlogs"
  and event.category == "authentication"
  and to_lower(azure.signinlogs.properties.resource_display_name) rlike "(.*)365(.*)"
  and azure.signinlogs.category in ("NonInteractiveUserSignInLogs", "SignInLogs")
  and event.outcome != "success"
  // for tuning review azure.signinlogs.properties.status.error_code
  // https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes

// keep only relevant fields
| keep target_time_window, event.dataset, event.category, azure.signinlogs.properties.resource_display_name, azure.signinlogs.category, event.outcome, azure.signinlogs.properties.user_principal_name, source.ip

// count the number of login sources and failed login attempts
| stats
  login_source_count = count(source.ip),
  failed_login_count = count(*) by target_time_window, azure.signinlogs.properties.user_principal_name

// filter for users with more than 20 login sources or failed login attempts
| where (login_source_count >= 20 or failed_login_count >= 20)
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




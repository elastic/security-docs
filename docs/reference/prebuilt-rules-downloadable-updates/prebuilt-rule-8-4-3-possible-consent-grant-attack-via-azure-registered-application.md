---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-3-possible-consent-grant-attack-via-azure-registered-application.html
---

# Possible Consent Grant Attack via Azure-Registered Application [prebuilt-rule-8-4-3-possible-consent-grant-attack-via-azure-registered-application]

Detects when a user grants permissions to an Azure-registered application or when an administrator grants tenant-wide permissions to an application. An adversary may create an Azure-registered application that requests access to data such as contact information, email, or documents.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*
* logs-o365*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants?view=o365-worldwide](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants?view=o365-worldwide)
* [https://www.cloud-architekt.net/detection-and-mitigation-consent-grant-attacks-azuread/](https://www.cloud-architekt.net/detection-and-mitigation-consent-grant-attacks-azuread/)
* [https://docs.microsoft.com/en-us/defender-cloud-apps/investigate-risky-oauth#how-to-detect-risky-oauth-apps](https://docs.microsoft.com/en-us/defender-cloud-apps/investigate-risky-oauth#how-to-detect-risky-oauth-apps)

**Tags**:

* Elastic
* Cloud
* Azure
* Continuous Monitoring
* Microsoft 365
* SecOps
* Identity and Access
* Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3578]

## Triage and analysis

## Investigating Possible Consent Grant Attack via Azure-Registered Application

In an illicit consent grant attack, the attacker creates an Azure-registered application that requests access to data such as contact information, email, or documents. The attacker then tricks an end user into granting that application consent to access their data either through a phishing attack, or by injecting illicit code into a trusted website. After the illicit application has been granted consent, it has account-level access to data without the need for an organizational account. Normal remediation steps like resetting passwords for breached accounts or requiring multi-factor authentication (MFA) on accounts are not effective against this type of attack, since these are third-party applications and are external to the organization.

Official Microsoft guidance for detecting and remediating this attack can be found [here](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants).

### Possible investigation steps

- From the Azure AD portal, Review the application that was granted permissions:
  - Click on the `Review permissions` button on the `Permissions` blade of the application.
  - An app should require only permissions related to the app's purpose. If that's not the case, the app might be risky.
  - Apps that require high privileges or admin consent are more likely to be risky.
- Investigate the app and the publisher. The following characteristics can indicate suspicious apps:
  -  A low number of downloads.
  -  Low rating or score or bad comments.
  -  Apps with a suspicious publisher or website.
  -  Apps whose last update is not recent. This might indicate an app that is no longer supported.
- Export and examine the [Oauth app auditing](https://docs.microsoft.com/en-us/defender-cloud-apps/manage-app-permissions#oauth-app-auditing) to identify users affected.

## False positive analysis

- This mechanism can be used legitimately. Malicious applications abuse the same workflow used by legitimate apps. Thus, analysts must review each app consent to ensure that only desired apps are granted access.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Identify the possible impact of the incident and prioritize accordingly; the following actions can help you gain context:
    - Identify the account role in the cloud environment.
    - Assess the criticality of affected services and servers.
    - Work with your IT team to identify and minimize the impact on users.
    - Identify if the attacker is moving laterally and compromising other accounts, servers, or services.
    - Identify any regulatory or legal ramifications related to this activity.
- Disable the malicious application to stop user access and the application access to your data.
- Revoke the application Oauth consent grant. The `Remove-AzureADOAuth2PermissionGrant` cmdlet can be used to complete this task.
- Remove the service principal application role assignment. The `Remove-AzureADServiceAppRoleAssignment` cmdlet can be used to complete this task.
- Revoke the refresh token for all users assigned to the application. Azure provides a [playbook](https://github.com/Azure/Azure-Sentinel/tree/master/Playbooks/Revoke-AADSignInSessions) for this task.
- [Report](https://docs.microsoft.com/en-us/defender-cloud-apps/manage-app-permissions#send-feedback) the application as malicious to Microsoft.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords or delete API keys as needed to revoke the attacker's access to the environment. Work with your IT teams to minimize the impact on business operations during these actions.
- Investigate the potential for data compromise from the user's email and file sharing services. Activate your Data Loss incident response playbook.
- Disable the permission for a user to set consent permission on their behalf.
  - Enable the [Admin consent request](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/configure-admin-consent-workflow) feature.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_4300]

```js
event.dataset:(azure.activitylogs or azure.auditlogs or o365.audit) and
  (
    azure.activitylogs.operation_name:"Consent to application" or
    azure.auditlogs.operation_name:"Consent to application" or
    o365.audit.Operation:"Consent to application."
  ) and
  event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Phishing
    * ID: T1566
    * Reference URL: [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)

* Sub-technique:

    * Name: Spearphishing Link
    * ID: T1566.002
    * Reference URL: [https://attack.mitre.org/techniques/T1566/002/](https://attack.mitre.org/techniques/T1566/002/)

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Steal Application Access Token
    * ID: T1528
    * Reference URL: [https://attack.mitre.org/techniques/T1528/](https://attack.mitre.org/techniques/T1528/)




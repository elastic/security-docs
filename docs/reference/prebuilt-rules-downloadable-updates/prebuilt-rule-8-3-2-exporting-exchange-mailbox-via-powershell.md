---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-exporting-exchange-mailbox-via-powershell.html
---

# Exporting Exchange Mailbox via PowerShell [prebuilt-rule-8-3-2-exporting-exchange-mailbox-via-powershell]

Identifies the use of the Exchange PowerShell cmdlet, New-MailBoxExportRequest, to export the contents of a primary mailbox or archive to a .pst file. Adversaries may target user email to collect sensitive information.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/](https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/)
* [https://docs.microsoft.com/en-us/powershell/module/exchange/new-mailboxexportrequest?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/new-mailboxexportrequest?view=exchange-ps)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Collection
* has_guide

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2395]

## Triage and analysis

## Investigating Exporting Exchange Mailbox via PowerShell

The `New-MailBoxExportRequest` cmdlet is used to begin the process of exporting contents of a primary mailbox or archive
to a .pst file. Note that this is done on a per-mailbox basis and this cmdlet is available only in on-premises Exchange.

Attackers can abuse this functionality in preparation for exfiltrating contents, which is likely to contain sensitive
and strategic data.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Investigate the export operation:
  - Identify the user account that performed the action and whether it should perform this kind of action.
  - Contact the account owner and confirm whether they are aware of this activity.
  - Check if this operation was approved and performed according to the organization's change management policy.
  - Retrieve the operation status and use the `Get-MailboxExportRequest` cmdlet to review previous requests.
  - By default, no group in Exchange has the privilege to import or export mailboxes. Investigate administrators that
  assigned the "Mailbox Import Export" privilege for abnormal activity.
- Investigate if there is a significant quantity of export requests in the alert timeframe. This operation is done on
a per-mailbox basis and can be part of a mass export.
- If the operation was completed successfully:
  - Check if the file is on the path specified in the command.
  - Investigate if the file was compressed, archived, or retrieved by the attacker for exfiltration.

## False positive analysis

- This mechanism can be used legitimately. Analysts can dismiss the alert if the administrator is aware of the activity
and it is done with proper approval.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- If the involved host is not the Exchange server, isolate the host to prevent further post-compromise behavior.
- Use the `Remove-MailboxExportRequest` cmdlet to remove fully or partially completed export requests.
- Prioritize cases that involve personally identifiable information (PII) or other classified data.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Review the privileges of users with the "Mailbox Import Export" privilege to ensure that the least privilege principle
is being followed.
- Run a full scan using the antimalware tool in place. This scan can reveal additional artifacts left in the system,
persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2761]

```js
process where event.type == "start" and
  process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and process.args : "New-MailboxExportRequest*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data from Local System
    * ID: T1005
    * Reference URL: [https://attack.mitre.org/techniques/T1005/](https://attack.mitre.org/techniques/T1005/)

* Technique:

    * Name: Email Collection
    * ID: T1114
    * Reference URL: [https://attack.mitre.org/techniques/T1114/](https://attack.mitre.org/techniques/T1114/)

* Sub-technique:

    * Name: Remote Email Collection
    * ID: T1114.002
    * Reference URL: [https://attack.mitre.org/techniques/T1114/002/](https://attack.mitre.org/techniques/T1114/002/)




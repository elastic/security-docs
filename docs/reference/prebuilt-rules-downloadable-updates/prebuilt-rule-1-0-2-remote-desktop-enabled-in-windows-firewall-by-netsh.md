---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-remote-desktop-enabled-in-windows-firewall-by-netsh.html
---

# Remote Desktop Enabled in Windows Firewall by Netsh [prebuilt-rule-1-0-2-remote-desktop-enabled-in-windows-firewall-by-netsh]

Identifies use of the network shell utility (netsh.exe) to enable inbound Remote Desktop Protocol (RDP) connections in the Windows Firewall.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1540]

## Triage and analysis

## Investigating Remote Desktop Enabled in Windows Firewall by Netsh

Microsoft Remote Desktop Protocol (RDP) is a proprietary Microsoft protocol that enables remote connections to other
computers, typically over TCP port 3389.

Attackers can use RDP to conduct their actions interactively. Ransomware operators frequently use RDP to access
victim servers, often using privileged accounts.

This rule detects the creation of a Windows Firewall inbound rule that would allow inbound RDP traffic using the
`netsh.exe` utility.

### Possible investigation steps

- Identify the user account which performed the action and whether it should perform this kind of action.
- Contact the user to check if they are aware of the operation.
- Investigate the script execution chain (parent process tree).
- Investigate other alerts related to the user/host in the last 48 hours.
- Check whether it makes sense to enable RDP to this host, given its role in the environment.
- Check if the host is directly exposed to the internet.
- Check whether privileged accounts accessed the host shortly after the modification.

## False positive analysis

- The `netsh.exe` utility can be used legitimately. Check whether the user should be performing this kind of activity, whether the user is aware
of it, whether RDP should be open, and whether the action exposes the environment to unnecessary risks.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- If RDP is needed, make sure to secure it:
  - Allowlist RDP traffic to specific trusted hosts.
  - Restrict RDP logins to authorized non-administrator accounts, where possible.
- Quarantine the implicated host to prevent further post-compromise behavior.
- Review the implicated account's privileges.

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1778]

```js
process where event.type in ("start", "process_started") and
 (process.name : "netsh.exe" or process.pe.original_file_name == "netsh.exe") and
 process.args : ("localport=3389", "RemoteDesktop", "group=\"remote desktop\"") and
 process.args : ("action=allow", "enable=Yes", "enable")
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

    * Name: Disable or Modify System Firewall
    * ID: T1562.004
    * Reference URL: [https://attack.mitre.org/techniques/T1562/004/](https://attack.mitre.org/techniques/T1562/004/)




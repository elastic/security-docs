---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-microsoft-iis-connection-strings-decryption.html
---

# Microsoft IIS Connection Strings Decryption [prebuilt-rule-8-17-4-microsoft-iis-connection-strings-decryption]

Identifies use of aspnet_regiis to decrypt Microsoft IIS connection strings. An attacker with Microsoft IIS web server access via a webshell or alike can decrypt and dump any hardcoded connection strings, such as the MSSQL service account password using aspnet_regiis command.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.forwarded*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*
* logs-crowdstrike.fdr*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 33

**References**:

* [https://blog.netspi.com/decrypting-iis-passwords-to-break-out-of-the-dmz-part-1/](https://blog.netspi.com/decrypting-iis-passwords-to-break-out-of-the-dmz-part-1/)
* [https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/greenbug-espionage-telco-south-asia](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/greenbug-espionage-telco-south-asia)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 313

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4715]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft IIS Connection Strings Decryption**

Microsoft IIS often stores sensitive connection strings in encrypted form to secure database credentials. The `aspnet_regiis` tool can decrypt these strings, a feature intended for legitimate administrative tasks. However, attackers with access to the IIS server, possibly via a webshell, can exploit this to extract credentials. The detection rule identifies suspicious use of `aspnet_regiis` by monitoring process execution with specific arguments, flagging potential credential access attempts.

**Possible investigation steps**

* Review the process execution details to confirm the presence of aspnet_regiis.exe with the specific arguments "connectionStrings" and "-pdf" to ensure the alert is not a false positive.
* Check the user account associated with the process execution to determine if it is a legitimate administrative account or a potentially compromised one.
* Investigate the source of the process initiation by examining the parent process and any related processes to identify if a webshell or unauthorized script triggered the execution.
* Analyze recent login activities and access logs on the IIS server to identify any unusual or unauthorized access patterns that could indicate a compromise.
* Review the server’s security logs and any available network traffic data to detect any signs of data exfiltration or further malicious activity following the decryption attempt.
* Assess the integrity and security of the IIS server by checking for any unauthorized changes or suspicious files that may have been introduced by an attacker.

**False positive analysis**

* Routine administrative tasks using aspnet_regiis for legitimate configuration changes can trigger the rule. To manage this, create exceptions for known maintenance windows or specific administrator accounts performing these tasks.
* Automated deployment scripts that include aspnet_regiis for setting up or updating IIS configurations may cause false positives. Exclude these scripts by identifying their unique process arguments or execution paths.
* Scheduled tasks or services that periodically run aspnet_regiis for configuration validation or updates might be flagged. Document these tasks and exclude them based on their scheduled times or associated service accounts.
* Development environments where developers frequently use aspnet_regiis for testing purposes can generate alerts. Consider excluding specific development servers or user accounts from the rule to reduce noise.
* Security tools or monitoring solutions that simulate attacks for testing purposes may inadvertently trigger the rule. Coordinate with security teams to whitelist these tools or their specific test scenarios.

**Response and remediation**

* Immediately isolate the affected IIS server from the network to prevent further unauthorized access and potential data exfiltration.
* Terminate any suspicious processes related to aspnet_regiis.exe to halt any ongoing decryption attempts.
* Conduct a thorough review of IIS server logs and webshell activity to identify the source of the compromise and any other affected systems.
* Change all credentials associated with the decrypted connection strings, including database passwords and service account credentials, to prevent unauthorized access.
* Restore the IIS server from a known good backup taken before the compromise, ensuring that any webshells or malicious scripts are removed.
* Implement enhanced monitoring and alerting for any future unauthorized use of aspnet_regiis.exe, focusing on the specific arguments used in the detection query.
* Escalate the incident to the security operations center (SOC) or relevant incident response team for further investigation and to assess the broader impact on the organization.


## Rule query [_rule_query_5670]

```js
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "aspnet_regiis.exe" or ?process.pe.original_file_name == "aspnet_regiis.exe") and
  process.args : "connectionStrings" and process.args : "-pdf"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-adfind-command-activity.html
---

# AdFind Command Activity [prebuilt-rule-8-1-1-adfind-command-activity]

This rule detects the Active Directory query tool, AdFind.exe. AdFind has legitimate purposes, but it is frequently leveraged by threat actors to perform post-exploitation Active Directory reconnaissance. The AdFind tool has been observed in Trickbot, Ryuk, Maze, and FIN6 campaigns. For Winlogbeat, this rule requires Sysmon.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [http://www.joeware.net/freetools/tools/adfind/](http://www.joeware.net/freetools/tools/adfind/)
* [https://thedfirreport.com/2020/05/08/adfind-recon/](https://thedfirreport.com/2020/05/08/adfind-recon/)
* [https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html](https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.md)
* [https://www.cybereason.com/blog/dropping-anchor-from-a-trickbot-infection-to-the-discovery-of-the-anchor-malware](https://www.cybereason.com/blog/dropping-anchor-from-a-trickbot-infection-to-the-discovery-of-the-anchor-malware)
* [https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html](https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.md)
* [https://usa.visa.com/dam/VCOM/global/support-legal/documents/fin6-cybercrime-group-expands-threat-To-ecommerce-merchants.pdf](https://usa.visa.com/dam/VCOM/global/support-legal/documents/fin6-cybercrime-group-expands-threat-To-ecommerce-merchants.pdf)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Discovery

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1765]

## Triage and analysis

## Investigating AdFind Command Activity

[AdFind](http://www.joeware.net/freetools/tools/adfind/) is a freely available command-line tool used to retrieve information
from Active Directory (AD). Network discovery and enumeration tools like `AdFind` are useful to adversaries in the same
ways they are effective for network administrators. This tool provides quick ability to scope AD person/computer objects
and understand subnets and domain information. There are many [examples](https://thedfirreport.com/category/adfind/) of
this tool being adopted by ransomware and criminal groups and used in compromises.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Examine the command line to determine what information was retrieved by the tool.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.

## False positive analysis

- This rule has a high chance to produce false positives as it is a legitimate tool used by network administrators.
- If this activity is expected and noisy in your environment, consider adding exceptions — preferably with a combination
of user and command line conditions.
- Malicious behavior with `AdFind` should be investigated as part of a step within an attack chain. It doesn't happen in
isolation, so reviewing previous logs/activity from impacted machines can be very telling.

## Related rules

- Windows Network Enumeration - 7b8bfc26-81d2-435e-965c-d722ee397ef1
- Enumeration of Administrator Accounts - 871ea072-1b71-4def-b016-6278b505138d
- Enumeration Command Spawned via WMIPrvSE - 770e0c4d-b998-41e5-a62e-c7901fd7f470

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_2039]

```js
process where event.type in ("start", "process_started") and
  (process.name : "AdFind.exe" or process.pe.original_file_name == "AdFind.exe") and
  process.args : ("objectcategory=computer", "(objectcategory=computer)",
                  "objectcategory=person", "(objectcategory=person)",
                  "objectcategory=subnet", "(objectcategory=subnet)",
                  "objectcategory=group", "(objectcategory=group)",
                  "objectcategory=organizationalunit", "(objectcategory=organizationalunit)",
                  "objectcategory=attributeschema", "(objectcategory=attributeschema)",
                  "domainlist", "dcmodes", "adinfo", "dclist", "computers_pwnotreqd", "trustdmp")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Remote System Discovery
    * ID: T1018
    * Reference URL: [https://attack.mitre.org/techniques/T1018/](https://attack.mitre.org/techniques/T1018/)

* Technique:

    * Name: Permission Groups Discovery
    * ID: T1069
    * Reference URL: [https://attack.mitre.org/techniques/T1069/](https://attack.mitre.org/techniques/T1069/)

* Sub-technique:

    * Name: Domain Groups
    * ID: T1069.002
    * Reference URL: [https://attack.mitre.org/techniques/T1069/002/](https://attack.mitre.org/techniques/T1069/002/)

* Technique:

    * Name: Account Discovery
    * ID: T1087
    * Reference URL: [https://attack.mitre.org/techniques/T1087/](https://attack.mitre.org/techniques/T1087/)

* Sub-technique:

    * Name: Domain Account
    * ID: T1087.002
    * Reference URL: [https://attack.mitre.org/techniques/T1087/002/](https://attack.mitre.org/techniques/T1087/002/)

* Technique:

    * Name: Domain Trust Discovery
    * ID: T1482
    * Reference URL: [https://attack.mitre.org/techniques/T1482/](https://attack.mitre.org/techniques/T1482/)




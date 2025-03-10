---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-adfind-command-activity.html
---

# AdFind Command Activity [prebuilt-rule-0-14-2-adfind-command-activity]

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

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1316]

## Triage and analysis

## Investigating AdFind Command Activity

[AdFind](http://www.joeware.net/freetools/tools/adfind/) is a freely available command-line tool used to retrieve information from
Activity Directory (AD). Network discovery and enumeration tools like `AdFind` are useful to adversaries in the same ways
they are effective for network administrators. This tool provides quick ability to scope AD person/computer objects and
understand subnets and domain information. There are many [examples](https://thedfirreport.com/category/adfind/)
observed where this tool has been adopted by ransomware and criminal groups and used in compromises.

### Possible investigation steps:
- `AdFind` is a legitimate Active Directory enumeration tool used by network administrators, it's important to understand
the source of the activity.  This could involve identifying the account using `AdFind` and determining based on the command-lines
what information was retrieved, then further determining if these actions are in scope of that user's traditional responsibilities.
- In multiple public references, `AdFind` is leveraged after initial access is achieved, review previous activity on impacted
machine looking for suspicious indicators such as previous anti-virus/EDR alerts, phishing emails received, or network traffic
to suspicious infrastructure

## False Positive Analysis
- This rule has the high chance to produce false positives as it is a legitimate tool used by network administrators. One
option could be whitelisting specific users or groups who use the tool as part of their daily responsibilities. This can
be done by leveraging the exception workflow in the Kibana Security App or Elasticsearch API to tune this rule to your environment
- Malicious behavior with `AdFind` should be investigated as part of a step within an attack chain. It doesn't happen in
isolation, so reviewing previous logs/activity from impacted machines could be very telling.

## Related Rules
- Windows Network Enumeration
- Enumeration of Administrator Accounts
- Enumeration Command Spawned via WMIPrvSE

## Response and Remediation
- Immediate response should be taken to validate activity, investigate and potentially isolate activity to prevent further
post-compromise behavior
- It's important to understand that `AdFind` is an Active Directory enumeration tool and can be used for malicious or legitimate
purposes, so understanding the intent behind the activity will help determine the appropropriate response.

## Rule query [_rule_query_1449]

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

* Technique:

    * Name: Remote System Discovery
    * ID: T1018
    * Reference URL: [https://attack.mitre.org/techniques/T1018/](https://attack.mitre.org/techniques/T1018/)




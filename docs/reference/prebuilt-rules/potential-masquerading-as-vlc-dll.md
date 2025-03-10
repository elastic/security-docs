---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-masquerading-as-vlc-dll.html
---

# Potential Masquerading as VLC DLL [potential-masquerading-as-vlc-dll]

Identifies instances of VLC-related DLLs which are not signed by the original developer. Attackers may name their payload as legitimate applications to blend into the environment, or embedding its malicious code within legitimate applications to deceive machine learning algorithms by incorporating authentic and benign code.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.library-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* Data Source: Elastic Defend
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Persistence
* Rule Type: BBR

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_752]

```js
library where host.os.type == "windows" and event.action == "load" and
  dll.name : ("libvlc.dll", "libvlccore.dll", "axvlc.dll") and
  not (
    dll.code_signature.subject_name : ("VideoLAN", "716F2E5E-A03A-486B-BC67-9B18474B9D51")
    and dll.code_signature.trusted == true
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Invalid Code Signature
    * ID: T1036.001
    * Reference URL: [https://attack.mitre.org/techniques/T1036/001/](https://attack.mitre.org/techniques/T1036/001/)

* Sub-technique:

    * Name: Match Legitimate Name or Location
    * ID: T1036.005
    * Reference URL: [https://attack.mitre.org/techniques/T1036/005/](https://attack.mitre.org/techniques/T1036/005/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Compromise Host Software Binary
    * ID: T1554
    * Reference URL: [https://attack.mitre.org/techniques/T1554/](https://attack.mitre.org/techniques/T1554/)




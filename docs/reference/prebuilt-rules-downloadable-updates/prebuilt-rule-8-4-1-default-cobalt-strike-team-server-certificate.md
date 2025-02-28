---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-default-cobalt-strike-team-server-certificate.html
---

# Default Cobalt Strike Team Server Certificate [prebuilt-rule-8-4-1-default-cobalt-strike-team-server-certificate]

This rule detects the use of the default Cobalt Strike Team Server TLS certificate. Cobalt Strike is software for Adversary Simulations and Red Team Operations which are security assessments that replicate the tactics and techniques of an advanced adversary in a network. Modifications to the Packetbeat configuration can be made to include MD5 and SHA256 hashing algorithms (the default is SHA1). See the References section for additional information on module configuration.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* filebeat-*
* packetbeat-*
* logs-endpoint.events.*

**Severity**: critical

**Risk score**: 99

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://attack.mitre.org/software/S0154/](https://attack.mitre.org/software/S0154/)
* [https://www.cobaltstrike.com/help-setup-collaboration](https://www.cobaltstrike.com/help-setup-collaboration)
* [/beats/docs/reference/ingestion-tools/beats-packetbeat/configuration-tls.md](beats://reference/packetbeat/configuration-tls.md)
* [https://www.elastic.co/guide/en/beats/filebeat/7.9/filebeat-module-suricata.html](https://www.elastic.co/guide/en/beats/filebeat/7.9/filebeat-module-suricata.html)
* [https://www.elastic.co/guide/en/beats/filebeat/7.9/filebeat-module-zeek.html](https://www.elastic.co/guide/en/beats/filebeat/7.9/filebeat-module-zeek.html)
* [https://www.elastic.co/security-labs/collecting-cobalt-strike-beacons-with-the-elastic-stack](https://www.elastic.co/security-labs/collecting-cobalt-strike-beacons-with-the-elastic-stack)

**Tags**:

* Command and Control
* Post-Execution
* Threat Detection
* Elastic
* Network
* Host

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2664]

## Threat intel

While Cobalt Strike is intended to be used for penetration tests and IR training, it is frequently used by actual threat actors (TA) such as APT19, APT29, APT32, APT41, FIN6, DarkHydrus, CopyKittens, Cobalt Group, Leviathan, and many other unnamed criminal TAs. This rule uses high-confidence atomic indicators, so alerts should be investigated rapidly.

## Rule query [_rule_query_3053]

```js
event.category:(network or network_traffic) and (tls.server.hash.md5:950098276A495286EB2A2556FBAB6D83 or
  tls.server.hash.sha1:6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C or
  tls.server.hash.sha256:87F2085C32B6A2CC709B365F55873E207A9CAA10BFFECF2FD16D3CF9D94D390C)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Application Layer Protocol
    * ID: T1071
    * Reference URL: [https://attack.mitre.org/techniques/T1071/](https://attack.mitre.org/techniques/T1071/)

* Sub-technique:

    * Name: Web Protocols
    * ID: T1071.001
    * Reference URL: [https://attack.mitre.org/techniques/T1071/001/](https://attack.mitre.org/techniques/T1071/001/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-roshal-archive-rar-or-powershell-file-downloaded-from-the-internet.html
---

# Roshal Archive (RAR) or PowerShell File Downloaded from the Internet [prebuilt-rule-8-3-3-roshal-archive-rar-or-powershell-file-downloaded-from-the-internet]

Detects a Roshal Archive (RAR) file or PowerShell script downloaded from the internet by an internal host. Gaining initial access to a system and then downloading encoded or encrypted tools to move laterally is a common practice for adversaries as a way to protect their more valuable tools and tactics, techniques, and procedures (TTPs). This may be atypical behavior for a managed network and can be indicative of malware, exfiltration, or command and control.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* filebeat-*
* packetbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.md)
* [https://www.justice.gov/opa/press-release/file/1084361/download](https://www.justice.gov/opa/press-release/file/1084361/download)
* [https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)

**Tags**:

* Elastic
* Network
* Threat Detection
* Command and Control
* Host

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2983]

## Threat intel

This activity has been observed in FIN7 campaigns.

## Rule query [_rule_query_3472]

```js
event.category:(network or network_traffic) and network.protocol:http and
  (url.extension:(ps1 or rar) or url.path:(*.ps1 or *.rar)) and
    not destination.ip:(
      10.0.0.0/8 or
      127.0.0.0/8 or
      169.254.0.0/16 or
      172.16.0.0/12 or
      192.0.0.0/24 or
      192.0.0.0/29 or
      192.0.0.8/32 or
      192.0.0.9/32 or
      192.0.0.10/32 or
      192.0.0.170/32 or
      192.0.0.171/32 or
      192.0.2.0/24 or
      192.31.196.0/24 or
      192.52.193.0/24 or
      192.168.0.0/16 or
      192.88.99.0/24 or
      224.0.0.0/4 or
      100.64.0.0/10 or
      192.175.48.0/24 or
      198.18.0.0/15 or
      198.51.100.0/24 or
      203.0.113.0/24 or
      240.0.0.0/4 or
      "::1" or
      "FE80::/10" or
      "FF00::/8"
    ) and
    source.ip:(
      10.0.0.0/8 or
      172.16.0.0/12 or
      192.168.0.0/16
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Ingress Tool Transfer
    * ID: T1105
    * Reference URL: [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)




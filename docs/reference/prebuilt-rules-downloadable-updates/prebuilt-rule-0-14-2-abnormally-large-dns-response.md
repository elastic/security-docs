---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-abnormally-large-dns-response.html
---

# Abnormally Large DNS Response [prebuilt-rule-0-14-2-abnormally-large-dns-response]

Specially crafted DNS requests can manipulate a known overflow vulnerability in some Windows DNS servers which result in Remote Code Execution (RCE) or a Denial of Service (DoS) from crashing the service.

**Rule type**: query

**Rule indices**:

* packetbeat-*
* filebeat-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/](https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/)
* [https://msrc-blog.microsoft.com/2020/07/14/july-2020-security-update-cve-2020-1350-vulnerability-in-windows-domain-name-system-dns-server/](https://msrc-blog.microsoft.com/2020/07/14/july-2020-security-update-cve-2020-1350-vulnerability-in-windows-domain-name-system-dns-server/)
* [https://github.com/maxpl0it/CVE-2020-1350-DoS](https://github.com/maxpl0it/CVE-2020-1350-DoS)

**Tags**:

* Elastic
* Network
* Threat Detection
* Lateral Movement

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1317]

## Triage and analysis

## Investigating Large DNS Responses
Detection alerts from this rule indicate possible anomalous activity around large byte DNS responses from a Windows DNS
server. This detection rule was created based on activity represented in exploitation of vulnerability (CVE-2020-1350)
also known as [SigRed](https://www.elastic.co/blog/detection-rules-for-sigred-vulnerability) during July 2020.

### Possible investigation steps:
- This specific rule is sourced from network log activity such as DNS or network level data. It's important to validate
the source of the incoming traffic and determine if this activity has been observed previously within an environment.
- Activity can be further investigated and validated by reviewing available corresponding Intrusion Detection Signatures (IDS) alerts associated with activity.
- Further examination can be made by reviewing the `dns.question_type` network fieldset with a protocol analyzer, such as Zeek, Packetbeat, or Suricata, for `SIG` or `RRSIG` data.
- Validate the patch level and OS of the targeted DNS server to validate the observed activity was not large-scale Internet vulnerability scanning.
- Validate that the source of the network activity was not from an authorized vulnerability scan or compromise assessment.

### False Positive Analysis
- Based on this rule which looks for a threshold of 60k bytes, it is possible for activity to be generated under 65k bytes
and related to legitimate behavior.  In packet capture files received by the [SANS Internet Storm Center](https://isc.sans.edu/forums/diary/PATCH+NOW+SIGRed+CVE20201350+Microsoft+DNS+Server+Vulnerability/26356/), byte responses
were all observed as greater than 65k bytes.
- This activity has the ability to be triggered from compliance/vulnerability scanning or compromise assessment, it's
important to determine the source of the activity and potential whitelist the source host


## Related Rules
- Unusual Child Process of dns.exe
- Unusual File Modification by dns.exe

## Response and Remediation
- Review and implement the above detection logic within your environment using technology such as Endpoint security, Winlogbeat, Packetbeat, or network security monitoring (NSM) platforms such as Zeek or Suricata.
- Ensure that you have deployed the latest Microsoft [Security Update](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1350) (Monthly Rollup or Security Only) and restart the
patched machines. If unable to patch immediately: Microsoft [released](https://support.microsoft.com/en-us/help/4569509/windows-dns-server-remote-code-execution-vulnerability) a registry-based workaround that doesn’t require a
restart. This can be used as a temporary solution before the patch is applied.
- Maintain backups of your critical systems to aid in quick recovery.
- Perform routine vulnerability scans of your systems, monitor [CISA advisories](https://us-cert.cisa.gov/ncas/current-activity) and patch identified vulnerabilities.
- If observed true positive activity, implement a remediation plan and monitor host-based artifacts for additional post-exploitation behavior.

## Rule query [_rule_query_1467]

```js
event.category:(network or network_traffic) and destination.port:53 and
  (event.dataset:zeek.dns or type:dns or event.type:connection) and network.bytes > 60000
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Exploitation of Remote Services
    * ID: T1210
    * Reference URL: [https://attack.mitre.org/techniques/T1210/](https://attack.mitre.org/techniques/T1210/)




---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-statistical-model-detected-c2-beaconing-activity.html
---

# Statistical Model Detected C2 Beaconing Activity [prebuilt-rule-8-17-4-statistical-model-detected-c2-beaconing-activity]

A statistical model has identified command-and-control (C2) beaconing activity. Beaconing can help attackers maintain stealthy communication with their C2 servers, receive instructions and payloads, exfiltrate data and maintain persistence in a network.

**Rule type**: query

**Rule indices**:

* ml_beaconing.all

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-1h ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [Prebuilt anomaly detection jobs](docs-content://reference/security/prebuilt-anomaly-detection-jobs.md)
* [https://docs.elastic.co/en/integrations/beaconing](https://docs.elastic.co/en/integrations/beaconing)
* [https://www.elastic.co/security-labs/identifying-beaconing-malware-using-elastic](https://www.elastic.co/security-labs/identifying-beaconing-malware-using-elastic)

**Tags**:

* Domain: Network
* Use Case: C2 Beaconing Detection
* Tactic: Command and Control
* Resources: Investigation Guide

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4115]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Statistical Model Detected C2 Beaconing Activity**

Statistical models analyze network traffic patterns to identify anomalies indicative of C2 beaconing, a tactic used by attackers to maintain covert communication with compromised systems. Adversaries exploit this by sending periodic signals to C2 servers, often mimicking legitimate traffic. The detection rule leverages statistical analysis to flag unusual beaconing while excluding known benign processes, thus highlighting potential threats without overwhelming analysts with false positives.

**Possible investigation steps**

* Review the network traffic logs to identify the source and destination IP addresses associated with the beaconing activity flagged by the statistical model.
* Cross-reference the identified IP addresses with threat intelligence databases to determine if they are associated with known malicious C2 servers.
* Analyze the frequency and pattern of the beaconing signals to assess whether they mimic legitimate traffic or exhibit characteristics typical of C2 communication.
* Investigate the processes running on the source system to identify any suspicious or unauthorized applications that may be responsible for the beaconing activity.
* Check for any recent changes or anomalies in the system’s configuration or installed software that could indicate a compromise.
* Examine the historical network activity of the source system to identify any other unusual patterns or connections that may suggest a broader compromise.

**False positive analysis**

* The rule may flag legitimate processes that exhibit periodic network communication patterns similar to C2 beaconing. Processes like "metricbeat.exe" and "packetbeat.exe" are known to generate regular network traffic for monitoring purposes.
* Users can manage these false positives by adding exceptions for these known benign processes in the detection rule, ensuring they are not flagged as threats.
* Regularly review and update the list of excluded processes to include any new legitimate applications that may mimic beaconing behavior, reducing unnecessary alerts.
* Consider implementing a whitelist approach for processes that are verified as non-threatening, allowing the statistical model to focus on truly anomalous activities.
* Engage with network and security teams to understand the normal traffic patterns of your environment, which can help in refining the detection rule and minimizing false positives.

**Response and remediation**

* Isolate the affected system from the network to prevent further communication with the C2 server and limit potential data exfiltration.
* Terminate any suspicious processes identified by the alert that are not part of the known benign list, ensuring that any malicious activity is halted.
* Conduct a thorough scan of the isolated system using updated antivirus and anti-malware tools to identify and remove any malicious software or files.
* Review and analyze network logs to identify any other systems that may have communicated with the same C2 server, and apply similar containment measures to those systems.
* Restore the affected system from a known good backup to ensure that any persistent threats are removed, and verify the integrity of the restored system.
* Implement network segmentation to limit the ability of compromised systems to communicate with critical infrastructure and sensitive data.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional measures are needed to prevent recurrence.


## Setup [_setup_1002]

**Setup**

The rule requires the Network Beaconing Identification integration assets to be installed, as well as network logs collected by the Elastic Defend or Network Packet Capture integrations.

**Network Beaconing Identification Setup**

The Network Beaconing Identification integration consists of a statistical framework to identify C2 beaconing activity in network logs.

**Prerequisite Requirements:**

* Fleet is required for Network Beaconing Identification.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).
* Network events collected by the [Elastic Defend](https://docs.elastic.co/en/integrations/endpoint) or [Network Packet Capture](https://docs.elastic.co/integrations/network_traffic) integration.
* To install Elastic Defend, refer to the [documentation](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).
* To add the Network Packet Capture integration to an Elastic Agent policy, refer to [this](docs-content://reference/ingestion-tools/fleet/add-integration-to-policy.md) guide.

**The following steps should be executed to install assets associated with the Network Beaconing Identification integration:**

* Go to the Kibana homepage. Under Management, click Integrations.
* In the query bar, search for Network Beaconing Identification and select the integration to see more details about it.
* Follow the instructions under the ***Installation*** section.


## Rule query [_rule_query_5132]

```js
beacon_stats.is_beaconing: true and
not process.name: ("WaAppAgent.exe" or "metricbeat.exe" or "packetbeat.exe" or "WindowsAzureGuestAgent.exe" or "HealthService.exe" or "Widgets.exe" or "lsass.exe" or "msedgewebview2.exe" or
                   "MsMpEng.exe" or "OUTLOOK.EXE" or "msteams.exe" or "FileSyncHelper.exe" or "SearchProtocolHost.exe" or "Creative Cloud.exe" or "ms-teams.exe" or "ms-teamsupdate.exe" or
                   "curl.exe" or "rundll32.exe" or "MsSense.exe" or "wermgr.exe" or "java" or "olk.exe" or "iexplore.exe" or "NetworkManager" or "packetbeat" or "Ssms.exe" or "NisSrv.exe" or
                   "gamingservices.exe" or "appidcertstorecheck.exe" or "POWERPNT.EXE" or "miiserver.exe" or "Grammarly.Desktop.exe" or "SnagitEditor.exe" or "CRWindowsClientService.exe" or
                   "agentbeat" or "dnf" or "yum" or "apt"
                  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Web Service
    * ID: T1102
    * Reference URL: [https://attack.mitre.org/techniques/T1102/](https://attack.mitre.org/techniques/T1102/)

* Sub-technique:

    * Name: Bidirectional Communication
    * ID: T1102.002
    * Reference URL: [https://attack.mitre.org/techniques/T1102/002/](https://attack.mitre.org/techniques/T1102/002/)




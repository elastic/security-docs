---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-uid-elevation-from-previously-unknown-executable.html
---

# UID Elevation from Previously Unknown Executable [prebuilt-rule-8-17-4-uid-elevation-from-previously-unknown-executable]

Monitors for the elevation of regular user permissions to root permissions through a previously unknown executable. Attackers may attempt to evade detection by hijacking the execution flow and hooking certain functions/syscalls through a rootkit in order to provide easy access to root via a special modified command.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4542]

**Triage and analysis**

[TBC: QUOTE]
**Investigating UID Elevation from Previously Unknown Executable**

In Linux environments, UID elevation is a process where a user’s permissions are increased, often to root level, allowing full system control. Adversaries exploit this by using unknown executables to hijack execution flow, often via rootkits, to gain unauthorized root access. The detection rule identifies such activities by monitoring for UID changes initiated by non-standard executables, excluding known safe paths and processes, thus highlighting potential privilege escalation attempts.

**Possible investigation steps**

* Review the process details to identify the unknown executable that triggered the alert, focusing on the process.executable field to determine its path and origin.
* Examine the parent process information using process.parent.name to understand the context in which the unknown executable was launched, checking for any unusual or unexpected shell activity.
* Investigate the user account associated with the UID change by analyzing the user.id field to determine if the account has a history of privilege escalation attempts or if it has been compromised.
* Check the system logs for any recent changes or installations that might have introduced the unknown executable, focusing on the time frame around the event.action:"uid_change".
* Assess the network activity around the time of the alert to identify any potential external connections or data exfiltration attempts that might correlate with the privilege escalation.
* Cross-reference the executable path and name against known threat intelligence databases to determine if it is associated with any known malicious activity or rootkits.
* If possible, perform a forensic analysis of the executable to understand its behavior and potential impact on the system, looking for signs of function or syscall hooking as indicated in the rule description.

**False positive analysis**

* Executables in custom directories may trigger false positives if they are legitimate but not included in the known safe paths. Users can mitigate this by adding these directories to the exclusion list in the detection rule.
* Scripts or binaries executed by system administrators from non-standard locations for maintenance or deployment purposes might be flagged. To handle this, users should document and exclude these specific processes or paths if they are verified as safe.
* Development or testing environments where new executables are frequently introduced can cause alerts. Users should consider creating exceptions for these environments or paths to reduce noise while ensuring they are monitored separately for any unusual activity.
* Automated scripts or tools that perform legitimate UID changes but are not part of the standard system paths can be excluded by adding their specific executable paths or names to the rule’s exception list.
* Temporary or ephemeral processes that are part of containerized applications might be flagged. Users should review and exclude these processes if they are confirmed to be part of normal operations.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes identified by the detection rule that are not part of the known safe paths or processes.
* Conduct a thorough review of the affected system’s logs to identify any additional indicators of compromise or related suspicious activities.
* Remove any unauthorized or unknown executables found on the system, especially those involved in the UID elevation attempt.
* Restore the system from a known good backup if any rootkits or persistent threats are detected that cannot be easily removed.
* Update and patch the system to the latest security standards to close any vulnerabilities that may have been exploited.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the potential impact on other systems.


## Setup [_setup_1374]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a Linux System:**

* Go to the Kibana home page and click Add integrations.
* In the query bar, search for Elastic Defend and select the integration to see more details about it.
* Click Add Elastic Defend.
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, either Traditional Endpoints or Cloud Workloads.
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest to select "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in New agent policy name. If other agent policies already exist, you can click the Existing hosts tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click Save and Continue.
* To complete the integration, select Add Elastic Agent to your hosts and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_5534]

```js
host.os.type:"linux" and event.category:"process" and event.action:"uid_change" and event.type:"change" and user.id:"0"
and process.parent.name:("bash" or "dash" or "sh" or "tcsh" or "csh" or "zsh" or "ksh" or "fish") and not (
  process.executable:(
    /bin/* or /usr/bin/* or /sbin/* or /usr/sbin/* or /snap/* or /tmp/newroot/* or /var/lib/docker/* or /usr/local/* or
    /opt/psa/admin/* or /usr/lib/snapd/snap-confine or /opt/dynatrace/* or /opt/microsoft/* or
    /var/lib/snapd/snap/bin/node or /opt/gitlab/embedded/sbin/logrotate or /etc/apt/universal-hooks/* or
    /opt/puppetlabs/puppet/bin/puppet or /opt/cisco/* or /run/k3s/containerd/* or /usr/lib/postfix/sbin/master or
    /usr/libexec/postfix/local or /var/lib/snapd/snap/bin/postgresql* or /opt/puppetlabs/puppet/bin/ruby
  ) or
  process.name:(
    "bash" or "dash" or "sh" or "tcsh" or "csh" or "zsh" or "ksh" or "fish" or "sudo" or "su" or "apt" or "apt-get" or
    "aptitude" or "squid" or "snap" or "fusermount" or "pkexec" or "umount" or "master" or "omsbaseline" or "dzdo" or
    "sandfly" or "logrotate" or "nix-installer"
  ) or
  process.args:/usr/bin/python*
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: KernelCallbackTable
    * ID: T1574.013
    * Reference URL: [https://attack.mitre.org/techniques/T1574/013/](https://attack.mitre.org/techniques/T1574/013/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Rootkit
    * ID: T1014
    * Reference URL: [https://attack.mitre.org/techniques/T1014/](https://attack.mitre.org/techniques/T1014/)




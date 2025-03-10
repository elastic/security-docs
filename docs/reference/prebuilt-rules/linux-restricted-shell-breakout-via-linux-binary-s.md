---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/linux-restricted-shell-breakout-via-linux-binary-s.html
---

# Linux Restricted Shell Breakout via Linux Binary(s) [linux-restricted-shell-breakout-via-linux-binary-s]

Identifies the abuse of a Linux binary to break out of a restricted shell or environment by spawning an interactive system shell. The activity of spawning a shell from a binary is not common behavior for a user or system administrator, and may indicate an attempt to evade detection, increase capabilities or enhance the stability of an adversary.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://gtfobins.github.io/gtfobins/apt/](https://gtfobins.github.io/gtfobins/apt/)
* [https://gtfobins.github.io/gtfobins/apt-get/](https://gtfobins.github.io/gtfobins/apt-get/)
* [https://gtfobins.github.io/gtfobins/nawk/](https://gtfobins.github.io/gtfobins/nawk/)
* [https://gtfobins.github.io/gtfobins/mawk/](https://gtfobins.github.io/gtfobins/mawk/)
* [https://gtfobins.github.io/gtfobins/awk/](https://gtfobins.github.io/gtfobins/awk/)
* [https://gtfobins.github.io/gtfobins/gawk/](https://gtfobins.github.io/gtfobins/gawk/)
* [https://gtfobins.github.io/gtfobins/busybox/](https://gtfobins.github.io/gtfobins/busybox/)
* [https://gtfobins.github.io/gtfobins/c89/](https://gtfobins.github.io/gtfobins/c89/)
* [https://gtfobins.github.io/gtfobins/c99/](https://gtfobins.github.io/gtfobins/c99/)
* [https://gtfobins.github.io/gtfobins/cpulimit/](https://gtfobins.github.io/gtfobins/cpulimit/)
* [https://gtfobins.github.io/gtfobins/crash/](https://gtfobins.github.io/gtfobins/crash/)
* [https://gtfobins.github.io/gtfobins/env/](https://gtfobins.github.io/gtfobins/env/)
* [https://gtfobins.github.io/gtfobins/expect/](https://gtfobins.github.io/gtfobins/expect/)
* [https://gtfobins.github.io/gtfobins/find/](https://gtfobins.github.io/gtfobins/find/)
* [https://gtfobins.github.io/gtfobins/flock/](https://gtfobins.github.io/gtfobins/flock/)
* [https://gtfobins.github.io/gtfobins/gcc/](https://gtfobins.github.io/gtfobins/gcc/)
* [https://gtfobins.github.io/gtfobins/mysql/](https://gtfobins.github.io/gtfobins/mysql/)
* [https://gtfobins.github.io/gtfobins/nice/](https://gtfobins.github.io/gtfobins/nice/)
* [https://gtfobins.github.io/gtfobins/ssh/](https://gtfobins.github.io/gtfobins/ssh/)
* [https://gtfobins.github.io/gtfobins/vi/](https://gtfobins.github.io/gtfobins/vi/)
* [https://gtfobins.github.io/gtfobins/vim/](https://gtfobins.github.io/gtfobins/vim/)
* [https://gtfobins.github.io/gtfobins/capsh/](https://gtfobins.github.io/gtfobins/capsh/)
* [https://gtfobins.github.io/gtfobins/byebug/](https://gtfobins.github.io/gtfobins/byebug/)
* [https://gtfobins.github.io/gtfobins/git/](https://gtfobins.github.io/gtfobins/git/)
* [https://gtfobins.github.io/gtfobins/ftp/](https://gtfobins.github.io/gtfobins/ftp/)
* [https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 114

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_476]

**Triage and analysis**

**Investigating Linux Restricted Shell Breakout via Linux Binary(s)**

Detection alerts from this rule indicate that a Linux utility has been abused to breakout of restricted shells or environments by spawning an interactive system shell. Here are some possible avenues of investigation: - Examine the entry point to the host and user in action via the Analyse View. - Identify the session entry leader and session user - Examine the contents of session leading to the abuse via the Session View. - Examine the command execution pattern in the session, which may lead to suspricous activities - Examine the execution of commands in the spawned shell. - Identify imment threat to the system from the executed commands - Take necessary incident response actions to contain any malicious behviour caused via this execution.

**Related rules**

* A malicious spawned shell can execute any of the possible MITTRE ATT&CK vectors mainly to impair defences.
* Hence its adviced to enable defence evasion and privilige escalation rules accordingly in your environment

**Response and remediation**

Initiate the incident response process based on the outcome of the triage.

* If the triage releaved suspicious netwrok activity from the malicious spawned shell,
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware execution via the maliciously spawned shell,
* Search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* If the triage revelaed defence evasion for imparing defenses
* Isolate the involved host to prevent further post-compromise behavior.
* Identified the disabled security guard components on the host and take necessary steps in renebaling the same.
* If any tools have been disbaled / uninstalled or config tampered work towards reenabling the same.
* If the triage revelaed addition of persistence mechanism exploit like auto start scripts
* Isolate further login to the systems that can initae auto start scripts.
* Identify the auto start scripts and disable and remove the same from the systems
* If the triage revealed data crawling or data export via remote copy
* Investigate credential exposure on systems compromised / used / decoded by the attacker during the data crawling
* Intiate compromised credential deactivation and credential rotation process for all exposed crednetials.
* Investiagte if any IPR data was accessed during the data crawling and take appropriate actions.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_306]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a Linux System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, either "Traditional Endpoints" or "Cloud Workloads".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).

Session View uses process data collected by the Elastic Defend integration, but this data is not always collected by default. Session View is available on enterprise subscription for versions 8.3 and above.

**To confirm that Session View data is enabled:**

* Go to “Manage → Policies”, and edit one or more of your Elastic Defend integration policies.
* Select the” Policy settings” tab, then scroll down to the “Linux event collection” section near the bottom.
* Check the box for “Process events”, and turn on the “Include session data” toggle.
* If you want to include file and network alerts in Session View, check the boxes for “Network and File events”.
* If you want to enable terminal output capture, turn on the “Capture terminal output” toggle. For more information about the additional fields collected when this setting is enabled and the usage of Session View for Analysis refer to the [helper guide](docs-content://solutions/security/investigate/session-view.md).


## Rule query [_rule_query_511]

```js
process where host.os.type == "linux" and event.type == "start" and
(
  /* launching shell from capsh */
  (process.name == "capsh" and process.args == "--") or

  /* launching shells from unusual parents or parent+arg combos */
  (process.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and (
    (process.parent.name : "*awk" and process.parent.args : "BEGIN {system(*)}") or
    (process.parent.name == "git" and process.parent.args : ("*PAGER*", "!*sh", "exec *sh") or
     process.args : ("*PAGER*", "!*sh", "exec *sh") and not process.name == "ssh" ) or
    (process.parent.name : ("byebug", "ftp", "strace", "zip", "tar") and
    (
      process.parent.args : "BEGIN {system(*)}" or
      (process.parent.args : ("*PAGER*", "!*sh", "exec *sh") or process.args : ("*PAGER*", "!*sh", "exec *sh")) or
      (
        (process.parent.args : "exec=*sh" or (process.parent.args : "-I" and process.parent.args : "*sh")) or
        (process.args : "exec=*sh" or (process.args : "-I" and process.args : "*sh"))
        )
      )
    ) or

    /* shells specified in parent args */
    /* nice rule is broken in 8.2 */
    (process.parent.args : "*sh" and
      (
        (process.parent.name == "nice") or
        (process.parent.name == "cpulimit" and process.parent.args == "-f") or
        (process.parent.name == "find" and process.parent.args == "." and process.parent.args == "-exec" and
         process.parent.args == ";" and process.parent.args : "/bin/*sh") or
        (process.parent.name == "flock" and process.parent.args == "-u" and process.parent.args == "/")
      )
    )
  )) or

  /* shells specified in args */
  (process.args : "*sh" and (
    (process.parent.name == "crash" and process.parent.args == "-h") or
    (process.name == "sensible-pager" and process.parent.name in ("apt", "apt-get") and process.parent.args == "changelog")
    /* scope to include more sensible-pager invoked shells with different parent process to reduce noise and remove false positives */

  )) or
  (process.name == "busybox" and event.action == "exec" and process.args_count == 2 and process.args : "*sh" and not
   process.executable : "/var/lib/docker/overlay2/*/merged/bin/busybox" and not (process.parent.args == "init" and
   process.parent.args == "runc") and not process.parent.args in ("ls-remote", "push", "fetch") and not process.parent.name == "mkinitramfs") or
  (process.name == "env" and process.args_count == 2 and process.args : "*sh") or
  (process.parent.name in ("vi", "vim") and process.parent.args == "-c" and process.parent.args : ":!*sh") or
  (process.parent.name in ("c89", "c99", "gcc") and process.parent.args : "*sh,-s" and process.parent.args == "-wrapper") or
  (process.parent.name == "expect" and process.parent.args == "-c" and process.parent.args : "spawn *sh;interact") or
  (process.parent.name == "mysql" and process.parent.args == "-e" and process.parent.args : "\\!*sh") or
  (process.parent.name == "ssh" and process.parent.args == "-o" and process.parent.args : "ProxyCommand=;*sh 0<&2 1>&2")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)




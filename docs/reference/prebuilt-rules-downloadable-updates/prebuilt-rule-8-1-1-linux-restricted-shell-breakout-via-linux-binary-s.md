---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-linux-restricted-shell-breakout-via-linux-binary-s.html
---

# Linux Restricted Shell Breakout via  Linux Binary(s) [prebuilt-rule-8-1-1-linux-restricted-shell-breakout-via-linux-binary-s]

Identifies Linux binary(s) abuse to breakout of restricted shells or environments by spawning an interactive system shell. The linux utility(s) activity of spawning shell is not a standard use of the binary for a user or system administrator. It may indicates an attempt to improve the capabilities or stability of an adversary access.

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

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Execution
* GTFOBins

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1685]

## Triage and analysis

## Investigating Shell Evasion via Linux Utilities
Detection alerts from this rule indicate that a Linux utility has been abused to breakout of restricted shells or
environments by spawning an interactive system shell.
Here are some possible avenues of investigation:
- Examine the entry point to the host and user in action via the Analyse View.
  - Identify the session entry leader and session user
- Examine the contents of session leading to the abuse via the Session View.
  - Examine the command execution pattern in the session, which may lead to suspricous activities
- Examine the execution of commands in the spawned shell.
  - Identify imment threat to the system from the executed commands
  - Take necessary incident response actions to contain any malicious behviour caused via this execution.

## Related rules

- A malicious spawned shell can execute any of the possible MITTRE ATT&CK vectors mainly to impair defences.
- Hence its adviced to enable defence evasion and privilige escalation rules accordingly in your environment

## Response and remediation

Initiate the incident response process based on the outcome of the triage.

- If the triage releaved suspicious netwrok activity from the malicious spawned shell,
  - Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware execution via the maliciously spawned shell,
  - Search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that
  attackers could use to reinfect the system.
- If the triage revelaed defence evasion for imparing defenses
  - Isolate the involved host to prevent further post-compromise behavior.
  - Identified the disabled security guard components on the host and take necessary steps in renebaling the same.
  - If any tools have been disbaled / uninstalled or config tampered work towards reenabling the same.
- If the triage revelaed addition of persistence mechanism exploit like auto start scripts
  - Isolate further login to the systems that can initae auto start scripts.
  - Identify the auto start scripts and disable and remove the same from the systems
- If the triage revealed data crawling or data export via remote copy
  - Investigate credential exposure on systems compromised / used / decoded by the attacker during the data crawling
  - Intiate compromised credential deactivation and credential rotation process for all exposed crednetials.
  - Investiagte if any IPR data was accessed during the data crawling and take appropriate actions.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Config

The session view analysis for the command alerted is avalible in versions 8.2 and above.

## Rule query [_rule_query_1955]

```js
process where event.type == "start" and

  /* launch shells from unusual process */
  (process.name == "capsh" and process.args == "--") or

  /* launching shells from unusual parents or parent+arg combos */
  (process.name in ("bash", "sh", "dash","ash") and
    (process.parent.name in ("byebug","git","ftp")) or

    /* shells specified in parent args */
    /* nice rule is broken in 8.2 */
    (process.parent.args in ("/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash", "sh", "bash", "dash", "ash") and
        (process.parent.name == "nice") or
        (process.parent.name == "cpulimit" and process.parent.args == "-f") or
        (process.parent.name == "find" and process.parent.args == "-exec" and process.parent.args == ";") or
        (process.parent.name == "flock" and process.parent.args == "-u" and process.parent.args == "/")
    ) or

    /* shells specified in args */
    (process.args in ("/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash", "sh", "bash", "dash", "ash") and
        (process.parent.name == "crash" and process.parent.args == "-h") or
        (process.name == "sensible-pager" and process.parent.name in ("apt", "apt-get") and process.parent.args == "changelog")
        /* scope to include more sensible-pager invoked shells with different parent process to reduce noise and remove false positives */
    )
  ) or
  (process.name == "busybox" and process.args_count == 2 and process.args in ("/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash", "sh", "bash", "dash", "ash") )or
  (process.name == "env" and process.args_count == 2 and process.args in ("/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash", "sh", "bash", "dash", "ash")) or
  (process.parent.name in ("vi", "vim") and process.parent.args == "-c" and process.parent.args in (":!/bin/bash", ":!/bin/sh", ":!bash", ":!sh")) or
  (process.parent.name in ("c89","c99", "gcc") and process.parent.args in ("sh,-s", "bash,-s", "dash,-s", "ash,-s", "/bin/sh,-s", "/bin/bash,-s", "/bin/dash,-s", "/bin/ash,-s") and process.parent.args == "-wrapper") or
  (process.parent.name == "expect" and process.parent.args == "-c" and process.parent.args in ("spawn /bin/sh;interact", "spawn /bin/bash;interact", "spawn /bin/dash;interact", "spawn sh;interact", "spawn bash;interact", "spawn dash;interact")) or
  (process.parent.name == "mysql" and process.parent.args == "-e" and process.parent.args in ("\\!*sh", "\\!*bash", "\\!*dash", "\\!*/bin/sh", "\\!*/bin/bash", "\\!*/bin/dash")) or
  (process.parent.name == "ssh" and process.parent.args == "-o" and process.parent.args in ("ProxyCommand=;sh 0<&2 1>&2", "ProxyCommand=;bash 0<&2 1>&2", "ProxyCommand=;dash 0<&2 1>&2", "ProxyCommand=;/bin/sh 0<&2 1>&2", "ProxyCommand=;/bin/bash 0<&2 1>&2", "ProxyCommand=;/bin/dash 0<&2 1>&2")) or
  (process.parent.name in ("nawk", "mawk", "awk", "gawk") and process.parent.args : "BEGIN {system(*)}")
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




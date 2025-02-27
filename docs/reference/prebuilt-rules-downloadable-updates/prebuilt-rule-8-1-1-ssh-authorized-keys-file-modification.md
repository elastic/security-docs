---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-ssh-authorized-keys-file-modification.html
---

# SSH Authorized Keys File Modification [prebuilt-rule-8-1-1-ssh-authorized-keys-file-modification]

The Secure Shell (SSH) authorized_keys file specifies which users are allowed to log into a server using public key authentication. Adversaries may modify it to maintain persistence on a victim host by adding their own public key(s).

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Linux
* macOS
* Threat Detection
* Persistence

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1964]

```js
event.category:file and event.type:(change or creation) and
 file.name:("authorized_keys" or "authorized_keys2") and
 not process.executable:
             (/Library/Developer/CommandLineTools/usr/bin/git or
              /usr/local/Cellar/maven/*/libexec/bin/mvn or
              /Library/Java/JavaVirtualMachines/jdk*.jdk/Contents/Home/bin/java or
              /usr/bin/vim or
              /usr/local/Cellar/coreutils/*/bin/gcat or
              /usr/bin/bsdtar or
              /usr/bin/nautilus or
              /usr/bin/scp or
              /usr/bin/touch or
              /var/lib/docker/* or
              /usr/bin/google_guest_agent)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Sub-technique:

    * Name: SSH Authorized Keys
    * ID: T1098.004
    * Reference URL: [https://attack.mitre.org/techniques/T1098/004/](https://attack.mitre.org/techniques/T1098/004/)




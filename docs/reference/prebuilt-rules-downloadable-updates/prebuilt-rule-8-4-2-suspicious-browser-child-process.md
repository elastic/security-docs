---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-suspicious-browser-child-process.html
---

# Suspicious Browser Child Process [prebuilt-rule-8-4-2-suspicious-browser-child-process]

Identifies the execution of a suspicious browser child process. Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. With this technique, the user’s web browser is typically targeted for exploitation.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://objective-see.com/blog/blog_0x43.html](https://objective-see.com/blog/blog_0x43.html)
* [https://fr.slideshare.net/codeblue_jp/cb19-recent-apt-attack-on-crypto-exchange-employees-by-heungsoo-kang](https://fr.slideshare.net/codeblue_jp/cb19-recent-apt-attack-on-crypto-exchange-employees-by-heungsoo-kang)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Initial Access
* Execution

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3921]

```js
process where event.type in ("start", "process_started") and
  process.parent.name : ("Google Chrome", "Google Chrome Helper*", "firefox", "Opera", "Safari", "com.apple.WebKit.WebContent", "Microsoft Edge") and
  process.name : ("sh", "bash", "dash", "ksh", "tcsh", "zsh", "curl", "wget", "python*", "perl*", "php*", "osascript", "pwsh") and
  process.command_line != null and
  not process.command_line : "*/Library/Application Support/Microsoft/MAU*/Microsoft AutoUpdate.app/Contents/MacOS/msupdate*" and
  not process.args :
    (
      "hw.model",
      "IOPlatformExpertDevice",
      "/Volumes/Google Chrome/Google Chrome.app/Contents/Frameworks/*/Resources/install.sh",
      "--defaults-torrc",
      "*Chrome.app",
      "Framework.framework/Versions/*/Resources/keystone_promote_preflight.sh",
      "/Users/*/Library/Application Support/Google/Chrome/recovery/*/ChromeRecovery",
      "$DISPLAY",
      "*GIO_LAUNCHED_DESKTOP_FILE_PID=$$*",
      "/opt/homebrew/*",
      "/usr/local/*brew*"
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Exploitation for Client Execution
    * ID: T1203
    * Reference URL: [https://attack.mitre.org/techniques/T1203/](https://attack.mitre.org/techniques/T1203/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Drive-by Compromise
    * ID: T1189
    * Reference URL: [https://attack.mitre.org/techniques/T1189/](https://attack.mitre.org/techniques/T1189/)




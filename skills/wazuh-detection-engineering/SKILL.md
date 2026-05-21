---
name: wazuh-detection-engineering
description: Use this skill by 'detectionengineer_agent' subagent to create, modify, and manage custom Wazuh detection rules safely without altering default rules, ensuring persistence and proper configuration.
---


## Overview

This skill enables an agent to create, modify, and manage custom detection rules inside a **Wazuh Manager** without touching default ruleset files (which get overwritten on upgrades). All custom work is done under `/var/ossec/etc/rules/` and registered in `/var/ossec/etc/ossec.conf`.

---

## Key Wazuh Paths

| Path | Purpose |
|---|---|
| `/var/ossec/ruleset/rules/` | Default (built-in) rule files — **never edit directly** |
| `/var/ossec/etc/rules/` | Custom rule files — **always work here** |
| `/var/ossec/etc/ossec.conf` | Main config — register exclusions and custom rule dirs here |
| `/var/ossec/logs/ossec.log` | Manager log — check for rule load errors |

---

## Rule ID Ranges

| Range | Usage |
|---|---|
| `1 – 99999` | Reserved for Wazuh built-in rules |
| `100000 – 120000` | **Use this range for all custom rules** |

---

## Step-by-Step: Adding a Custom Rule

### STEP 1 — Find the Default Rule File

Search `/var/ossec/ruleset/rules/` for the file that contains the rule ID you want to extend or override.

```bash
grep -rl "<rule id=\"RULE_ID\"" /var/ossec/ruleset/rules/
```

**Example result:** `/var/ossec/ruleset/rules/0585-win-application_rules.xml`

Note the filename: `0585-win-application_rules.xml`

---

### STEP 2 — Check if a Custom File Already Exists

Look for a file named `custom-<DEFAULT_FILENAME>` inside `/var/ossec/etc/rules/`.

```bash
ls /var/ossec/etc/rules/ | grep "custom-0585-win-application_rules.xml"
```

**Two possible outcomes:**

#### ✅ Custom file EXISTS → Skip to Step 4
The custom file is already set up. Do **not** create a new one and do **not** touch the default file. Go directly to Step 4 to append your new rule.

#### ❌ Custom file DOES NOT EXIST → Continue to Step 3

---

### STEP 3 — Create the Custom Rule File (only if it doesn't exist)

#### 3a. Copy the default file content into the new custom file

```bash
cp /var/ossec/ruleset/rules/0585-win-application_rules.xml \
   /var/ossec/etc/rules/custom-0585-win-application_rules.xml
```

#### 3b. Set correct ownership and permissions

```bash
chown wazuh:wazuh /var/ossec/etc/rules/custom-0585-win-application_rules.xml
chmod 660 /var/ossec/etc/rules/custom-0585-win-application_rules.xml
```

> **Note:** On older Wazuh installs the owner may be `ossec:ossec` instead of `wazuh:wazuh`. Check existing files with `ls -la /var/ossec/etc/rules/` to confirm.

#### 3c. Exclude the default file in ossec.conf

Open `/var/ossec/etc/ossec.conf` and add a `<rule_exclude>` entry for the default filename **inside the `<ruleset>` block**:

```xml
<ruleset>
  <!-- Default ruleset -->
  <decoder_dir>ruleset/decoders</decoder_dir>
  <rule_dir>ruleset/rules</rule_dir>

  <!-- Excluded default files (replaced by custom copies) -->
  <rule_exclude>0585-win-application_rules.xml</rule_exclude>

  <!-- User-defined ruleset -->
  <decoder_dir>etc/decoders</decoder_dir>
  <rule_dir>etc/rules</rule_dir>
</ruleset>
```

**Important rules for editing ossec.conf:**
- Each excluded file gets its own `<rule_exclude>` line.
- Use only the **filename**, not the full path.
- The `<rule_dir>etc/rules</rule_dir>` line must already be present (it tells Wazuh to load everything under `/var/ossec/etc/rules/`). Add it if missing.
- **Do not duplicate** `<rule_exclude>` entries. Before adding, check if the entry already exists:

```bash
grep "0585-win-application_rules.xml" /var/ossec/etc/ossec.conf
```

---

### STEP 4 — Append the New Custom Rule to the Custom File

#### Custom Rule ID Check

Before adding a new rule ID, ensure it is unique in existing custom files:

```bash
grep -roh 'id="[0-9]*"' /var/ossec/etc/rules/*.xml 2>/dev/null | grep -o '[0-9]\+' | sort -n | uniq
```

Then Open `/var/ossec/etc/rules/custom-rule file name.xml`.

Use Python to insert the rule before the last </group> tag in the file (which is always the file-level closing wrapper tag, not a rule's inner <group> tag):

```
python3 - <<'EOF'
f = '/var/ossec/etc/rules/custom-FILENAME.xml'
new_rule = """  <rule id="RULE_ID" level="LEVEL" overwrite="no">
    <if_sid>PARENT_SID</if_sid>
    <description>YOUR DESCRIPTION HERE</description>
    <group>YOUR,GROUPS,HERE</group>
  </rule>"""

content = open(f).read()
idx = content.rfind('</group>')
if idx == -1:
    raise ValueError("No closing </group> tag found in file!")
content = content[:idx] + new_rule + '\n</group>\n'
open(f, 'w').write(content)
print("Rule inserted successfully.")
EOF
```

#### Key Rule Attributes

| Attribute / Tag | Description |
|---|---|
| `id` | Must be in range `100000–120000` for custom rules |
| `level` | Severity 1–15 (12+ = critical) |
| `overwrite="yes"` | Use when **replacing** an existing built-in rule with the same ID |
| `overwrite="no"` | Use when **adding a new** rule (default) |
| `<if_sid>` | Trigger only when this parent rule fires |
| `<if_matched_sid>` | Trigger if this rule fired within a time window |
| `<field name="">` | Match against a decoded field value (supports regex) |
| `<match>` | Simple string match against the log message |
| `<regex>` | Regex match against the log message |
| `<description>` | Alert title shown in Wazuh dashboard |
| `<mitre><id>` | MITRE ATT&CK technique mapping |
| `<group>` | Comma-separated group tags for categorization |

#### Regex Engine Decision Rules

1. Use `<match>` for simple literal text checks.
2. Use `<regex>` only for OSRegex-safe patterns.
3. If pattern needs grouped alternation like `(a|b)` or advanced regex behavior, use `type="pcre2"`.
4. Prefer decoded fields when available (`dstuser`, `srcip`, `uid`, `program_name`) instead of broad message regex.
5. If uncertain, default to field-based matching with `type="pcre2"`.


Refer to '/home/ubuntu/ango/fine-tunning/skills/wazuh-detection-engineering/references/ruleset-xml-syntax.md' for detailed XML structure and syntax rules.

Refer to '/home/ubuntu/ango/fine-tunning/skills/wazuh-detection-engineering/references/regular-expression-syntax-guide.md' for detailed regular expression syntax rules.

Refer to '/home/ubuntu/ango/fine-tunning/skills/wazuh-detection-engineering/references/pcre-regex-guide.md' for detailed PCRE syntax rules.
---

### STEP 5 — Validate and Test the Rule

#### 5a. Temporary Windows EventChannel Logtest Mode (when test windoes EventChannel rules) this step on Windows logs only not linux.

If you are testing a rule related to Windows which means:
- [ ] The log contains `win.system.*` or `win.eventdata.*` fields → YES, apply
- [ ] The parent rule SID is in range 60000–69999 → YES, apply  
- [ ] The rule file is `*win*` or `*windows*` → YES, apply

In this case, you need to temporarily adjust rule `60000` in the default Windows base file (/var/ossec/ruleset/rules/0575-win-base_rules.xml).

1) Backup the file first:

```bash
cp /var/ossec/ruleset/rules/0575-win-base_rules.xml /var/ossec/ruleset/rules/0575-win-base_rules.xml.bak-logtest
```

2) Edit the file:

```bash
sudo vi /var/ossec/ruleset/rules/0575-win-base_rules.xml
```

Use this temporary content for rule `60000`:

```xml
<rule id="60000" level="2">
    <!-- category>ossec</category -->
    <!-- decoded_as>windows_eventchannel</decoded_as -->
    <decoded_as>json</decoded_as>
    <field name="win.system.providerName">\.+</field>
    <options>no_full_log</options>
    <description>Group of windows rules.</description>
</rule>
```

3) Restart manager:

```bash
sudo systemctl restart wazuh-manager
```

4) Run `wazuh-logtest` and finish your validation.

5) **Mandatory rollback 0575-win-base_rules.xml after testing**: restore original file and restart again:

```bash
cp /var/ossec/ruleset/rules/0575-win-base_rules.xml.bak-logtest /var/ossec/ruleset/rules/0575-win-base_rules.xml
sudo systemctl restart wazuh-manager
```

> This change is for alert test-only. Do not leave the modified default file in place. revoke the change immediately after testing to avoid breaking other rules that rely on the original structure.

#### 5b. Base logtest

Use a full raw log line (provided by report/context) for `wazuh-logtest`:

```bash
echo "YOUR RAW LOG LINE HERE" | /var/ossec/bin/wazuh-logtest
```

Wait for the complete output before doing anything else.
Do not proceed until the command has fully returned and you have read every line.


Validation checks:
- Phase 1 completed
- Phase 2 completed
- Phase 2 does not contain `No decoder matched`
- Phase 3 completed (If the full log matches the condition defined in the new rule, the custom rule ID must appear here.)
- expected rule behavior is visible

Refer to '/home/ubuntu/ango/fine-tunning/skills/wazuh-detection-engineering/references/wazuh-logtest.guide.md' for detailed example usage.
---

### STEP 6 — Restart the Wazuh Manager

Apply all changes by restarting the manager:

```bash
systemctl restart wazuh-manager
```

---

### STEP 7 — Verify the Rule Loaded Successfully

Check the manager log for errors or confirmation:

```bash
grep -i "rule\|error\|warning" /var/ossec/logs/ossec.log | tail -50
```

Look for lines like:
- `Read_Rules(): DEBUG: Excluding rule: 0585-win-application_rules.xml` ✅
- `INFO: Loading rules from: /var/ossec/etc/rules/custom-0585-win-application_rules.xml` ✅

---

## Decision Logic Summary (Flowchart)

```
Agent receives request to add/modify a rule for RULE_ID
        │
        ▼
Find default file in /var/ossec/ruleset/rules/
that contains RULE_ID
        │
        ▼
Does custom-<FILENAME> exist in /var/ossec/etc/rules/?
        │
   YES ─┤                          ├─ NO
        │                          │
        ▼                          ▼
  Go to Step 4             Copy default file →
  (append rule)            custom-<FILENAME>
                           Set ownership/perms
                           Add <rule_exclude> in ossec.conf
                                   │
                                   ▼
                             Go to Step 4
                             (append rule)
                                   │
                                   ▼
                         Validate → Restart → Verify
```

---

## Common Mistakes to Avoid

| Mistake | Consequence | Correct Approach |
|---|---|---|
| Editing `/var/ossec/ruleset/rules/` directly | Changes lost on upgrade | Always work in `/var/ossec/etc/rules/` |
| Forgetting `<rule_exclude>` in ossec.conf | Both default and custom files load → duplicate rule conflict | Always exclude the default file when creating a custom copy |
| Using rule ID below 100000 for new rules | ID conflicts with built-in rules | Use IDs 100000–120000 |
| Missing unique ID check before adding new rule | Duplicate custom rule ID conflicts | Check existing IDs under `/var/ossec/etc/rules/*.xml` first |
| Using grouped alternation in OSRegex | Wazuh rule syntax/load errors | Use `type="pcre2"` for grouped alternation patterns |
| Testing with partial/non-real log strings | False pass/fail during tuning | Use full raw logs from report/context |
| Not restarting the manager after changes | Rules don't take effect | Always restart with `systemctl restart wazuh-manager` |
| Wrong file ownership on custom rule file | Wazuh can't read the file | Set `chown wazuh:wazuh` and `chmod 660` |
| Duplicate `<rule_exclude>` entries | Config warning, possible load issues | Check before adding: `grep FILENAME /var/ossec/etc/ossec.conf` |

---

## Quick Reference: ossec.conf Ruleset Block Template

```xml
<ruleset>
  <!-- Default ruleset -->
  <decoder_dir>ruleset/decoders</decoder_dir>
  <rule_dir>ruleset/rules</rule_dir>

  <!-- Excluded default files replaced by custom versions -->
  <rule_exclude>0215-policy_rules.xml</rule_exclude>
  <rule_exclude>0580-win-security_rules.xml</rule_exclude>
  <rule_exclude>0585-win-application_rules.xml</rule_exclude>

  <!-- CDB Lists -->
  <list>etc/lists/audit-keys</list>
  <list>etc/lists/security-eventchannel</list>

  <!-- User-defined ruleset (loads everything in etc/rules/) -->
  <decoder_dir>etc/decoders</decoder_dir>
  <rule_dir>etc/rules</rule_dir>
</ruleset>
```

---

## References

- Wazuh Ruleset XML Syntax: /home/ubuntu/ango/fine-tunning/skills/wazuh-detection-engineering/references/ruleset-xml-syntax.md

- Wazuh Regular Expression Syntax: /home/ubuntu/ango/fine-tunning/skills/wazuh-detection-engineering/references/regular-expression-syntax-guide.md

- Wazuh PCRE Syntax: /home/ubuntu/ango/fine-tunning/skills/wazuh-detection-engineering/references/pcre-regex-guide.md

- Wazuh Rule Testing Example: /home/ubuntu/ango/fine-tunning/skills/wazuh-detection-engineering/references/wazuh-logtest.guide.md

"""Manage documentation generation for pre-built rules."""

import re
import shutil
import textwrap
from pathlib import Path
from typing import List

import click
import json
import yaml


ROOT = Path(__file__).resolve().parent.parent
PREBUILT_RULES = ROOT.joinpath('prebuilt-rules-scripts')
GENERATED_ASCII = ROOT.joinpath('generated-ascii-files')
DEFAULT_KIBANA_RULES_DIR = str(Path().joinpath('x-pack', 'plugins', 'security_solution', 'server', 'lib',
                                               'detection_engine', 'prebuilt_rules', 'content', 'prepackaged_rules'))
DEFAULT_LOCAL_KIBANA = ROOT.joinpath('..', 'kibana')


class Version(tuple):

    def __new__(cls, version):
        if not isinstance(version, (int, list, tuple)):
            version = tuple(int(a) if a.isdigit() else a for a in re.split(r'[.-]', version))

        return version if isinstance(version, int) else tuple.__new__(cls, version)

    def bump(self):
        """Increment the version."""
        versions = list(self)
        versions[-1] += 1
        return Version(versions)

    def __str__(self):
        """Convert back to a string."""
        return ".".join(str(dig) for dig in self)

    @classmethod
    def sort_as_strings(cls, *version_strings: str, reverse=False) -> List[str]:
        versions = sorted([Version(v) for v in version_strings], reverse=reverse)
        return [str(v) for v in versions]


@click.group('root', context_settings={'help_option_names': ['-h', '--help']})
def root():
    """Commands for generating rule documentation."""


def _get_release_versions() -> List[Version]:
    final_files = PREBUILT_RULES.joinpath('diff-files', 'final-files').glob('*.json')
    versions = [str(f).rsplit('-', 1)[1].rsplit('.', 1)[0] for f in final_files]
    versions = [Version(v) for v in versions]
    return versions


def _get_last_release_version() -> str:
    """Get latest release version based on final-files versioning."""
    return str(max(_get_release_versions()))


def _sort_by_name(rule):
    return rule['name']


def _sort_tag_by_name(rule):
    return rule['tag']


def _translate_interval_period(interval):
    units = ""
    length = ""
    runtime = re.match(r"([0-9]+)([a-z]+)", interval, re.I)
    if runtime:
        runtime = runtime.groups()
    if len(runtime) == 2:
        if runtime[1] == 'm':
            units = "minutes"
        elif runtime[1] == 's':
            units = "seconds"
        elif runtime[1] == 'h':
            units = "hours"
        elif runtime[1] == 'H':
            units = "hours"
        elif runtime[1] == 'd':
            units = "days"
        elif runtime[1] == 'w':
            units = "weeks"
        elif runtime[1] == 'M':
            units = "months"
        elif runtime[1] == 'y':
            units = "years"
        else:
            units = ""
        length = runtime[0]
        if length == "1":
            units = units[:-1]
    return str(length + " " + units)


def _left_align(text):
    return '\n'.join([t.lstrip() for t in text.splitlines()])


def _convert_name_to_filename(name: str) -> str:
    name = re.sub(r'[():]', '', name.lower())
    name = re.sub(r'[ -+/\\]+', '-', name)
    name = re.sub(r'-+', '-', name)
    return name


def get_release_rules(package_version, local_kibana, rules_dir):
    rule_source_folder = Path(local_kibana).resolve().joinpath(rules_dir)
    assert rule_source_folder.exists(), f'Rules folder does not exist in {local_kibana}'

    rule_dict = []

    rule_files = rule_source_folder.glob('*.json')

    for rule_file in rule_files:
        with open(rule_file, 'r') as f:
            rule_json = json.load(f)
            rule_dict.append(rule_json)

    rule_dict = sorted(rule_dict, key=_sort_by_name)

    rule_dump = str(PREBUILT_RULES.joinpath('orig-rules-json-files', f'{package_version}-prebuilt-rule.json'))
    with open(rule_dump, "w") as f:
        json.dump(rule_dict, f, indent=2)

    click.echo(f'saved file: {rule_dump}')


def create_json_from_docs(package_version):
    """Create a json file of the exiting rule docs."""
    existing_rule_asciidocs = ROOT.joinpath('docs', 'detections', 'prebuilt-rules', 'rule-details')
    rule_asciidoc_files = existing_rule_asciidocs.glob("*.asciidoc")
    rule_dict = []

    name = ""
    description = ""
    false_pos = ""
    notes = ""

    is_desc = False
    is_false_pos = False
    is_notes = False

    for rule_asciidoc_file in rule_asciidoc_files:
        with open(rule_asciidoc_file, 'r') as f:
            text = f.readlines()
            for count, line in enumerate(text):
                if count == 1:
                    name = line.split("=== ")[1].replace("\n", "")
                    is_desc = True
                if is_desc:
                    description = description + line
                    if "*Rule type*" in text[count + 1]:
                        is_desc = False
                if "==== Potential false positives" in line:
                    is_false_pos = True
                    continue
                if is_false_pos:
                    false_pos = false_pos + line
                    if ("==== Rule query" in text[count]) or ("==== Investigation guide" in text[count]) or (
                            "==== Rule version history" in text[count]):
                        is_false_pos = False
                if "==== Investigation guide" in line:
                    is_notes = True
                    continue
                if is_notes:
                    notes = notes + line

            is_notes = False
            is_false_pos = False
            description = description.split("\n\n", 1)[1].replace("\n\n", "\n").rstrip()

            if "[[" in notes:
                notes = notes.split("[[")[0]
            if "\n==== Rule query\n" in notes:
                notes = notes.split("\n==== Rule query\n")[0]
            if "==== Rule query\n" in false_pos:
                false_pos = false_pos.split("\n\n==== Rule query\n")[0]
            if "==== Investigation guide\n" in false_pos:
                false_pos = false_pos.split("\n\n==== Investigation guide\n")[0]
            if "[[" in false_pos:
                false_pos = false_pos.split("[[")[0]

            rule_text = {"name": name, "description": description}

            if false_pos:
                rule_text['false_positives'] = [false_pos.lstrip()]
            if notes:
                notes_text = notes.rstrip()
                notes_text = notes_text[1:] if notes_text.startswith('\n') else notes_text
                rule_text['note'] = notes_text

            rule_dict.append(rule_text)
            name = ""
            description = ""
            false_pos = ""
            notes = ""

    rule_dict = sorted(rule_dict, key=_sort_by_name)
    diff_file = str(PREBUILT_RULES.joinpath('diff-files', 'gen-files', f'json-from-docs-{package_version}.json'))

    with open(diff_file, "w") as f:
        json.dump(rule_dict, f, indent=2)

    click.echo(f'saved file: {diff_file}')


def update_current_text(package_version):
    # Path to latest prebuilt rules JSON file
    rule_dump = str(PREBUILT_RULES.joinpath('orig-rules-json-files', f'{package_version}-prebuilt-rule.json'))
    with open(rule_dump, "r") as source:
        current_text = json.load(source)

    # Path to JSON file generated from existing documentation
    diff_file = str(PREBUILT_RULES.joinpath('diff-files', 'gen-files', f'json-from-docs-{package_version}.json'))
    with open(diff_file, "r") as source:
        updated_text = json.load(source)

    for rule in current_text:
        for new_text in updated_text:
            if rule['name'] == new_text['name']:
                new_text['description'] = rule['description']
                if 'false_positives' in new_text and 'false_positives' in rule:
                    new_text['false_positives'][0] = rule['false_positives'][0]
                if 'note' in new_text:
                    new_text['note'] = rule['note']

    # Output file with updated text from the documentation for previously existing
    # prebuilt rules. New rules are unchanged.

    with open(diff_file, "w") as fp:
        json.dump(current_text, fp, indent=2)

    click.echo(f'saved file: {diff_file}')


def get_rule_diff(package_version):
    previous_release = _get_last_release_version()
    err_str = f'Most recent detected version: {previous_release} !< {package_version}. '
    err_str += f'Remove {package_version} generated files (3) or specify a higher version to build'
    assert Version(package_version) > Version(previous_release), err_str

    # Path to the JSON rule file generated for this release
    diff_file = str(PREBUILT_RULES.joinpath('diff-files', 'gen-files', f'json-from-docs-{package_version}.json'))
    with open(diff_file, 'r') as source:
        lasted_rules_dict = json.load(source)

    # Path to the final JSON rule file generated for the previous release
    prev_final = str(PREBUILT_RULES.joinpath('diff-files', 'final-files', f'final-rule-file-{previous_release}.json'))
    with open(prev_final, 'r') as source:
        previous_rules_dict = json.load(source)

    diff_dict = []
    lasted_rules_dict = sorted(lasted_rules_dict, key=_sort_by_name)
    previous_rules_dict = sorted(previous_rules_dict, key=_sort_by_name)

    old_name = None
    counter = 0
    rule_found = False

    for new_rule in lasted_rules_dict:
        for old_rule in previous_rules_dict:
            if old_rule['rule_id'] == new_rule['rule_id']:
                if old_rule['name'] != new_rule['name']:
                    old_name = old_rule['name']

                old_file_name = _convert_name_to_filename(old_rule["name"])
                new_file_name = _convert_name_to_filename(new_rule["name"])
                file_name_changed = old_file_name != new_file_name

                old_rule['name'] = new_rule['name']
                if 'changelog' in old_rule:
                    new_rule['changelog'] = old_rule['changelog']
                if old_rule['version'] != new_rule['version']:
                    new_rule['last_update'] = package_version
                    if 'changelog' not in new_rule:
                        new_rule['changelog'] = {}
                        new_rule['changelog']['changes'] = []

                    if 'query' in new_rule:
                        if old_rule['query'] != new_rule['query']:
                            new_rule['changelog']['changes'].append({
                                "version": new_rule['version'],
                                "updated": new_rule['last_update'],
                                "pre_query": old_rule['query'],
                                "doc_text": "Updated query.",
                                "pre_name": old_name
                                })
                        elif old_rule['query'] == new_rule['query']:
                            new_rule['changelog']['changes'].append({
                                "version": new_rule['version'],
                                "updated": new_rule['last_update'],
                                "pre_query": old_rule['query'],
                                "doc_text": "Formatting only",
                                "pre_name": old_name
                            })
                    if 'query' not in new_rule:
                        new_rule['changelog']['changes'].append({
                            "version": new_rule['version'],
                            "updated": new_rule['last_update'],
                            "pre_query": "N/A",
                            "doc_text": "Formatting only",
                            "pre_name": old_name
                        })

                    if file_name_changed:
                        new_rule['changelog']['changes'][-1]['duplicate_old_file'] = old_file_name
                else:
                    new_rule['last_update'] = old_rule['last_update']

                diff_dict.append(new_rule)
                new_rule['added'] = old_rule['added']
                old_name = None
                rule_found = True

        if rule_found is False:
            new_rule['last_update'] = package_version
            new_rule['added'] = package_version
            diff_dict.append(new_rule)
            counter = counter + 1

        rule_found = False

    # Outputs the final JSON file from which the documentation is generated. Note
    # that this file is needed for the next release to compare future changes.
    final = str(PREBUILT_RULES.joinpath('diff-files', 'final-files', f'final-rule-file-{package_version}.json'))
    with open(final, "w") as fp:
        json.dump(diff_dict, fp, indent=2)

    click.echo(f'saved file: {final}')


def create_documentation(package_release):
    # Formats text using asciidoc syntax
    def format_text(text):
        return text.replace('\\n', '\n')

    # Path to the generated JSON file
    final_diff = str(PREBUILT_RULES.joinpath('diff-files', 'final-files', f'final-rule-file-{package_release}.json'))
    with open(final_diff, 'r') as source:
        rules_dict = json.load(source)

    sorted_rules = sorted(rules_dict, key=_sort_by_name)

    new_text = _left_align("""[[prebuilt-rules]]
    [role="xpack"]
    == Prebuilt rule reference

    This section lists all available prebuilt rules.

    IMPORTANT: To run {ml} prebuilt rules, you must have the
    https://www.elastic.co/subscriptions[appropriate license] or use a
    {ess-trial}[Cloud] deployment. All {ml} prebuilt rules are tagged with `ML`,
    and their rule type is `machine_learning`.

    [width="100%",options="header"]
    |==============================================
    |Rule |Description |Tags |Added |Version


    """)

    # Creates overview table

    for rule in sorted_rules:
        tag_strings = ""
        version_text = ""
        link_string = _convert_name_to_filename(rule["name"])
        new_text = new_text + "|<<" + link_string + ", " + rule['name'] + ">> |" + re.sub(' +', ' ',
                                                                                          rule['description'].replace(
                                                                                              '\n', ' '))
        for i in rule['tags']:
            tag_strings = tag_strings + "[" + i + "] "

        if rule['version'] == 1:
            version_text = str(rule['version'])
        if rule['version'] > 1 and rule.get('changelog'):
            version_text = str(rule['version']) + " <<" + link_string + "-history, Version history>>"

        new_text = new_text + " |" + tag_strings + " |" + rule['added'] + " |" + version_text + "\n\n"
        tag_strings = ""

    new_text = new_text + "|=============================================="

    shutil.rmtree(str(GENERATED_ASCII), ignore_errors=True)
    GENERATED_ASCII.mkdir(exist_ok=True)
    reference_asciidoc = str(GENERATED_ASCII.joinpath('prebuilt-rules-reference.asciidoc'))
    with open(reference_asciidoc, "w+") as f:
        f.write(new_text)

    # End overview table

    # Create files for each rule and the index (ToC) file

    rule_details_dir = GENERATED_ASCII.joinpath('rule-details')
    rule_details_dir.mkdir(exist_ok=True)

    file_text = ""
    rules_index_file = []
    rule_name_changed = False
    files_with_updated_rule_name = {}
    updated_queries = False

    for rule in sorted_rules:
        rule_link = _convert_name_to_filename(rule["name"])
        file_text = "[[" + rule_link + "]]\n=== " + rule['name'] + "\n\n"
        file_text = file_text + format_text(rule['description']) + "\n\n"
        file_text = file_text + "*Rule type*: " + rule['type'] + "\n\n"

        if 'machine_learning_job_id' in rule:
            # can be a list or str
            job_id = rule['machine_learning_job_id']
            jod_id_str = ', '.join(job_id) if isinstance(job_id, list) else job_id
            file_text = file_text + "*Machine learning job*: " + jod_id_str + "\n\n"
            file_text = file_text + "*Machine learning anomaly threshold*: " + str(rule['anomaly_threshold']) + "\n\n"
        if 'index' in rule:
            if len(rule['index']) != 0:
                file_text = file_text + "*Rule indices*:" + "\n\n"
                for i in rule['index']:
                    file_text = file_text + "* " + i + "\n"
            else:
                file_text = file_text + "*Rule index*: " + rule['index'] + "\n\n"

        file_text = file_text + "\n*Severity*: " + rule['severity'] + "\n\n"
        file_text = file_text + "*Risk score*: " + str(rule['risk_score']) + "\n\n"
        if 'interval' in rule:
            file_text = file_text + "*Runs every*: " + _translate_interval_period(rule['interval']) + "\n\n"
        if 'interval' not in rule:
            file_text = file_text + "*Runs every*: 5 minutes" + "\n\n"
        if 'from' in rule:
            file_text = file_text + "*Searches indices from*: " + rule[
                'from'] + " ({ref}/common-options.html#date-math[Date Math format], see also <<rule-schedule, `Additional look-back time`>>)" + "\n\n"
        if 'from' not in rule:
            file_text = file_text + "*Searches indices from*: now-6m" + " ({ref}/common-options.html#date-math[Date Math format], see also <<rule-schedule, `Additional look-back time`>>)" + "\n\n"
        if 'max_signals' in rule:
            file_text = file_text + "*Maximum alerts per execution*: " + str(rule['max_signals']) + "\n\n"
        if 'max_signals' not in rule:
            file_text = file_text + "*Maximum alerts per execution*: 100" + "\n\n"
        if 'references' in rule:
            if len(rule['references']) != 0:
                file_text = file_text + "*References*:\n\n"
                for i in rule['references']:
                    file_text = file_text + "* " + i + "\n"
            if len(rule['references']) != 0:
                file_text = file_text + "\n"

        file_text = file_text + "*Tags*:\n\n"
        for i in rule['tags']:
            file_text = file_text + "* " + i + "\n"
        if rule['version'] == 1:
            file_text = file_text + "\n*Version*: " + str(rule['version']) + "\n\n"
        # DEBUG
        # if rule['version'] > 1 and not rule.get('changelog'):
        #    print(rule_link)
        if rule['version'] > 1 and rule.get('changelog'):
            file_text = file_text + "\n*Version*: " + str(
                rule['version']) + " (<<" + rule_link + "-history, version history>>)" + "\n\n"

        file_text = file_text + "*Added ({stack} release)*: " + rule['added'] + "\n\n"
        if rule['version'] > 1:
            file_text = file_text + "*Last modified ({stack} release)*: " + rule['last_update'] + "\n\n"

        file_text = file_text + "*Rule authors*: "
        for count, i in enumerate(rule['author']):
            if count > 0:
                file_text = file_text + ", "

            file_text = file_text + i

        file_text = file_text + "\n\n"
        file_text = file_text + "*Rule license*: " + rule['license'] + "\n"
        if 'false_positives' in rule:
            if len(rule['false_positives']) != 0:
                file_text = file_text + "\n==== Potential false positives" + "\n\n"
                for i in rule['false_positives']:
                    file_text = file_text + format_text(i) + "\n"

        if 'note' in rule:
            file_text = file_text + "\n==== Investigation guide" + "\n\n"
            file_text = file_text + "\n[source,markdown]\n"
            file_text = file_text + "----------------------------------" + "\n"
            file_text = file_text + rule['note'] + "\n"
            file_text = file_text + "----------------------------------" + "\n\n"
        if 'query' in rule:
            file_text = file_text + "\n==== Rule query\n\n"
            file_text = file_text + "\n[source,js]\n"
            file_text = file_text + "----------------------------------" + "\n"
            file_text = file_text + re.sub(' +', ' ', textwrap.fill(rule['query'], width=70)) + "\n"
            file_text = file_text + "----------------------------------" + "\n\n"
        if 'filters' in rule:
            if len(rule['filters']) != 0:
                file_text = file_text + "==== Rule filters" + "\n\n"
                file_text = file_text + "[source,js]\n"
                file_text = file_text + "----------------------------------" + "\n"
                for i in rule['filters']:
                    file_text = file_text + json.dumps(i, sort_keys=True, indent=4) + "\n"
                file_text = file_text + "----------------------------------" + "\n\n"
        if 'threat' in rule:
            if len(rule['threat']) != 0:
                file_text = file_text + "==== Threat mapping" + "\n\n"
                is_first_loop = True
                for i in rule['threat']:
                    if is_first_loop:
                        file_text = file_text + "*Framework*: " + i['framework']
                        is_first_loop = False
                        if i['framework'] == "MITRE ATT&CK":
                            file_text = file_text + "^TM^"

                    file_text = file_text + "\n\n* Tactic:\n"
                    file_text = file_text + "** Name: " + i['tactic']['name'] + "\n"
                    file_text = file_text + "** ID: " + i['tactic']['id'] + "\n"
                    file_text = file_text + "** Reference URL: " + i['tactic']['reference'] + "\n"

                    if i.get('technique'):
                        file_text = file_text + "* Technique:\n"
                        file_text = file_text + "** Name: " + i['technique'][0]['name'] + "\n"
                        file_text = file_text + "** ID: " + i['technique'][0]['id'] + "\n"
                        file_text = file_text + "** Reference URL: " + i['technique'][0]['reference'] + "\n"

        if 'changelog' in rule:
            identifier = rule_link + "-history"
            file_text = file_text + "\n[[" + identifier + "]]\n"
            file_text = file_text + "==== Rule version history" + "\n\n"
            for i in reversed(rule['changelog']['changes']):
                file_text = file_text + "Version " + str(i['version']) + " (" + i['updated'] + " release)" + "::\n"
                if 'pre_name' in i:
                    if i['pre_name'] != None:
                        file_text = file_text + "* Rule name changed from: " + i['pre_name'] + "\n"
                        rule_name_changed = True
                        if i['updated'] == package_release:
                            rule_link_file = rule_link + ".asciidoc"
                            files_with_updated_rule_name[rule_link_file] = i.get('duplicate_old_file', i['pre_name'])
                if i['doc_text'] == "Updated query.":
                    if 'pre_name' in i:
                        if i['pre_name'] != None:
                            file_text = file_text + "+\n"

                    file_text = file_text + "* Updated query, changed from:\n+\n"
                    file_text = file_text + "[source, js]\n"
                    file_text = file_text + "----------------------------------" + "\n"
                    file_text = file_text + re.sub(' +', ' ', textwrap.fill(i['pre_query'], width=70)) + "\n"
                    file_text = file_text + "----------------------------------" + "\n\n"

                    updated_queries = True

                if i['doc_text'] != "Updated query." and rule_name_changed == False:
                    file_text = file_text + "* " + i['doc_text'] + "\n\n"

                rule_name_changed = False

        asciidoc_file = str(rule_details_dir.joinpath(f'{rule_link}.asciidoc'))

        with open(asciidoc_file, "w+") as f:
            f.write(file_text)

        rules_index_file.append("include::rule-details/" + rule_link + ".asciidoc[]")

    # Create index file

    index_file_text = ""

    for index_link in rules_index_file:
        index_file_text += index_link + "\n"

    index_file_write = str(GENERATED_ASCII.joinpath('rule-desc-index.asciidoc'))
    with open(index_file_write, "w+") as index_file_write:
        index_file_write.write(index_file_text)

    # Print files of rules with changed names to terminal

    print('\n')
    for new_file, old_file in sorted(files_with_updated_rule_name.items()):
        print(f'Name of rule changed in {new_file} - removing old file: {old_file}')
        old_path = rule_details_dir.joinpath(f'{old_file}.asciidoc')
        if old_path.exists():
            old_path.unlink()  # unlink(missing_ok=True) only in 3.8+
    print("\n")

    # END: Create files for each rule

    # START: Create rule changelog file. This needs updating each release to add
    # rules changed for the new release.

    version_history_page = _left_align("""[[prebuilt-rules-changelog]]
    == Prebuilt rule changes per release

    The following lists prebuilt rule updates per release. Only rules with
    significant modifications to their query or scope are listed. For detailed
    information about a rule's changes, see the rule's description page.

    """)

    # Rules that have been deleted so there is no need to add them manually after
    # generating the docs

    deleted_rules = _left_align("""
    These prebuilt rules have been removed:

    * Execution via Signed Binary
    * Suspicious Process spawning from Script Interpreter
    * Suspicious Script Object Execution

    These prebuilt rules have been updated:

    """)

    def add_version_updates(*update_versions):
        nonlocal version_history_page

        for update_version in update_versions:
            version_history_page = version_history_page + "[float]\n"
            version_history_page = version_history_page + "=== " + update_version + "\n\n"
            if update_version == "7.7.0":
                version_history_page = version_history_page + deleted_rules
            for r in sorted_rules:
                if 'changelog' in r:
                    for i in (r['changelog']['changes']):
                        if i['updated'] == update_version and i['doc_text'] != "Formatting only":
                            link_string = _convert_name_to_filename(r['name'])
                            version_history_page = version_history_page + "<<" + link_string + ">>\n\n"

    # anytime this is built and changes are made to any queries, it will be added as an entry, to be included in future
    #   doc generation
    changelog_entries_file = str(PREBUILT_RULES.joinpath('changelog-entries.yml'))
    with open(changelog_entries_file, 'r+') as f:
        changelog_entries = yaml.safe_load(f)

        if updated_queries and package_release not in changelog_entries:
            changelog_entries.append(package_release)
            yaml.safe_dump([package_release], f)
            click.echo(f'Changes to queries detected, added: {package_release} to changelog-entries.yml')

    version_updates = Version.sort_as_strings(*changelog_entries, reverse=True)
    add_version_updates(*version_updates)

    reference_asciidoc = str(GENERATED_ASCII.joinpath('prebuilt-rules-changelog.asciidoc'))
    with open(reference_asciidoc, "w+") as f:
        f.write(version_history_page)


@root.command('generate')
@click.argument('package-version')
@click.option('--rules-dir', '-d', default=DEFAULT_KIBANA_RULES_DIR, help='Path of rules in Kibana repo')
@click.option('--local-kibana', '-l', type=click.Path(exists=True, file_okay=False), default=str(DEFAULT_LOCAL_KIBANA),
              help='Location of local kibana repo')
def generate(package_version, rules_dir, local_kibana):
    """Generate pre-built rule documentation."""
    get_release_rules(package_version, local_kibana, rules_dir)
    create_json_from_docs(package_version)
    update_current_text(package_version)
    get_rule_diff(package_version)
    create_documentation(package_version)

    click.echo('Files staged to generated-ascii-files folder - move these over to docs/detections/prebuilt-rules')


if __name__ == '__main__':
    root(prog_name='generate')

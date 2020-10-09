import json
import textwrap
import toml
import os
import glob
from pathlib import Path
import re

# Compares the newly generated JSON file for the new release with the JSON file
# generated for the previous release. It checks if rule queries have been
# changed and updates the version history as required (changelog object).

def sort_by_name(rule):
    '''
    Helper to sort rule by name'''
    return rule['name']

# Path to the JSON rule file generated for this release

with open('diff-files/gen-files/updated-text-json-file-7.9.0.json', 'r') as source:
    lasted_rules_dict = json.load(source)

# Path to the final JSON rule file generated for the previous release
    
with open('diff-files/final-files/final-rule-file-7.8.0.json', 'r') as source:
    previous_rules_dict = json.load(source)
    
diff_dict = []
    
lasted_rules_dict = sorted(lasted_rules_dict, key=sort_by_name)

previous_rules_dict = sorted(previous_rules_dict, key=sort_by_name)

# oldRuleNames = []
# newRuleNames = []
oldName = None
counter = 0 
ruleFound = False
for new_rule in lasted_rules_dict:
    # if new_rule['name'] not in newRuleNames:
    #     newRuleNames.append(new_rule['name'])
    for old_rule in previous_rules_dict:
        # if old_rule['name'] not in oldRuleNames:
        #     oldRuleNames.append(old_rule['name'])
        if old_rule['rule_id'] == new_rule['rule_id']:
            if old_rule['name'] != new_rule['name']:
                oldName = old_rule['name']
            old_rule['name'] = new_rule['name']
            if 'changelog' in old_rule:
                new_rule['changelog'] = old_rule['changelog']
            if old_rule['version'] != new_rule['version']:
                new_rule['last_update'] = "7.10.0"
                if 'changelog' not in new_rule:
                    new_rule['changelog'] = {}
                    new_rule['changelog']['changes'] = []
                if 'query' in new_rule:
                    if old_rule['query'] != new_rule['query']:
                        new_rule['changelog']['changes'].append({"version": new_rule['version'], "updated": new_rule['last_update'], "pre_query": old_rule['query'], "doc_text": "Updated query.", "pre_name": oldName})
                    if old_rule['query'] == new_rule['query']:
                        new_rule['changelog']['changes'].append({"version": new_rule['version'], "updated": new_rule['last_update'], "pre_query": old_rule['query'], "doc_text": "Formatting only.", "pre_name": oldName})
                if 'query' not in new_rule:
                    new_rule['changelog']['changes'].append({"version": new_rule['version'], "updated": new_rule['last_update'], "pre_query": "N/A", "doc_text": "Formatting only.", "pre_name": oldName})
            else:
                new_rule['last_update'] = old_rule['last_update']
            diff_dict.append(new_rule)
            new_rule['added'] = old_rule['added']
            oldName = None
            ruleFound = True
    if ruleFound == False:
        new_rule['last_update'] = "7.10.0"
        new_rule['added'] = "7.10.0"
        diff_dict.append(new_rule)
        counter = counter + 1
    ruleFound = False

# Outputs the final JSON file from which the documentation is generated. Note
# that this file is needed for the next release to compare future changes.

with open("diff-files/final-files/final-rule-file-7.9.0.json", "w") as fp:
    json.dump(diff_dict, fp, indent=2)
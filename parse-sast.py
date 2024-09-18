#!/usr/bin/env python3

import argparse
from jsonpath_ng import jsonpath
from jsonpath_ng.ext import parse
from packaging.version import Version

import jinja2
import json
import sys
import os.path

def filePath(vulnerability):
    return vulnerability['location']['file']

def countSeverities(vulnerabilities):
    # Pre-define severities we expect so we don't have to sort later
    frequencies = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0,
        'Unknown': 0
    }

    for vulnerability in vulnerabilities:
        if vulnerability['severity'] in frequencies:
            frequencies[vulnerability['severity']] += 1
        else: # If we don't have a category for a severity create it here
            frequencies[vulnerability['severity']] = 1

    return frequencies

if __name__ == "__main__":
    jsonpath_expr = parse("$.vulnerabilities[*]")
    data = None
    raw_input = "".join(sys.stdin.readlines())
    try:
        data = json.loads(raw_input)
    except json.JSONDecodeError:
        if os.path.exists(raw_input) and os.path.isfile(raw_input):
            with open(raw_input, "r") as f:
                data = json.load(f)
        else:
            if not os.path.exists(raw_input):
                print(f"Path doesn't exist {raw_input}")
            elif not os.path.isfile(raw_input):
                print(f"Please enter a valid JSON file {raw_input}")

    if data is not None:
        vulnerabilities = [vuln.value for vuln in jsonpath_expr.find(data)]
        frequencies=countSeverities(vulnerabilities)

        project_dir = os.path.dirname(__file__)
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.join(project_dir, 'templates')))
        template = env.get_template('vulnerability_report.html')
        rendered = template.render(vulnerabilities=vulnerabilities, frequencies=countSeverities(vulnerabilities))
        print(rendered)
        sys.exit(0)
    else:
        print("No data or file path provided on stdin")
        sys.exit(1)

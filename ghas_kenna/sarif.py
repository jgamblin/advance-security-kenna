
import os
import json
import logging

from ghas_kenna.vulnerability import Vulnerability


def findSarifFiles(root: str) -> list:
    results = []
    if not os.path.exists(root):
        raise Exception("SARIF folder does not exist")

    for filename in os.listdir(root):
        filepath = os.path.join(root, filename)
        _, fileext = os.path.splitext(filepath)

        # Ignore everything that isn't a sarif file
        if fileext == ".sarif":
            results.append(filepath)

    return results


def createVulnerabilityList(root: str) -> list:
    results = []
    if not os.path.exists(root):
        raise Exception("SARIF file does not exist")

    logging.info("Loading SARIF file :: " + root)

    with open(root, 'r') as handle:
        sarif = json.load(handle)

        sarif_version = sarif.get('version', 'NA')
        logging.info("SARIF File Version :: " + sarif_version)

        for run in sarif.get('runs', []):
            tool = run.get('tool', {})
            # Tool name
            tool_name = tool.get('driver', {}).get('name')
            tool_version = tool.get('driver', {}).get('semanticVersion')
            logging.info(
                "SARIF Tool Name :: {} ({})".format(tool_name, tool_version)
            )

            # Tool rules
            rules = tool.get('driver', {}).get('rules')
            logging.info("SARIF Rules enabled :: " + str(len(rules)))

            # Process results
            sarif_results = run.get('results', [])
            logging.info("SARIF Results Count :: " + str(len(sarif_results)))

            for result in sarif_results:
                result_id = result.get('ruleId')
                rule = next(rl for rl in rules if rl["id"] == result_id)

                vuln = Vulnerability(result, rule)

                logging.debug("Created " + str(vuln))

                results.append(vuln)

    return results

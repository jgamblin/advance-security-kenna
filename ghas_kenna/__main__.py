
import os
import json
import logging
import argparse

from ghas_kenna.sarif import findSarifFiles, createVulnerabilityList
from ghas_kenna.vulnerability import Vulnerability
from ghas_kenna.kenna import Kenna


parser = argparse.ArgumentParser("advance-security-kenna")
parser.add_argument(
    '--debug',
    action="store_true",
    default=bool(os.environ.get('DEBUG'))
)
parser.add_argument(
    '-k', '--kenna-token',
    required=True,
    default=os.environ.get('TOKEN'),
    help="Kenna Token"
)
parser.add_argument(
    '-t', '--github-token',
    default=os.environ.get('GITHUB_TOKEN'),
    help="GitHub Token"
)
parser.add_argument(
    '-e', '--endpoint',
    required=True,
    default=os.environ.get('ENDPOINT')
)
parser.add_argument(
    '-a', '--application',
    default='/'.join([
        os.environ.get('GITHUB_SERVER_URL'),
        os.environ.get('GITHUB_REPOSITORY')
    ]),
    help="Kenna Application ID/Name"
)
parser.add_argument(
    '-c', '--connector',
    type=int,
    default=os.environ.get('KENNA_CONNECTOR_ID'),
    help="Kenna Connection ID"
)
parser.add_argument(
    '-i', '--input',
    default=os.path.join(os.getcwd(), "../results"),
    help="Folder/File with SARIF file(s)"
)
parser.add_argument(
    '--vulnerability-format',
    default="[CWE-{cwe}] {path}",
    help="Vulnerability Unique Identifier String",
)


arguments = parser.parse_args()

# Logging
logging.basicConfig(
    level=logging.DEBUG if arguments.debug else logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)

# Kenna Client
kenna_client = Kenna(
    endpoint=arguments.endpoint,
    token=arguments.kenna_token,
    connector=arguments.connector,
    application=arguments.application
)
# TODO: Check if we can authenticate to instance
# if not kenna_client.checkLogin():
#     logging.error("Failed to authentication")
#     raise Exception("Failed to authentication")

# List of SARIF files found
if os.path.isfile(arguments.input):
    sarif_files = [arguments.input]
else:
    sarif_files = findSarifFiles(arguments.input)
# List of vulnerabilities
vulnerabilities = []

logging.info("Application Name :: " + arguments.application)

# Set Vulnerability format string
Vulnerability.__IDENTIFIER__ = arguments.vulnerability_format
logging.debug(
    "Vulnerability format string :: " + arguments.vulnerability_format
)

# Process every SARIF file found
for sarif_file in sarif_files:
    new_vulns = createVulnerabilityList(sarif_file)

    vulnerabilities.extend(new_vulns)

logging.info("Vulnerabilities found :: " + str(len(vulnerabilities)))

# Generate data for Kenna
data = kenna_client.generateData(vulnerabilities)
# Write to file
with open('kenna-data.json', 'w') as handle:
    json.dump(data, handle, indent=2)
# Upload file
result = kenna_client.uploadFile('kenna-data.json')

if result.get("success") != "true":
    raise Exception("Upload Failed")

logging.info("Upload successful!")

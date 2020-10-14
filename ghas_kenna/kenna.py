
import pycurl
import urllib
import logging
import datetime
import requests


class Kenna():
    def __init__(self, endpoint, token, connector=None, application=None):
        """ 
        """
        self.endpoint = endpoint
        self.token = token

        self.connector = connector
        self.application = application

        self.session = requests.Session()
        self.session.headers.update({
            'X-Risk-Token': self.token
            # 'Content-Type': 'application/json'
        })

        logging.info("Kenna Endpoint :: " + endpoint)
        logging.debug("Kenna Token :: " + token)

    def getEndpoint(self, path: str = ''):
        return self.endpoint + path

    def checkLogin(self) -> bool:
        # https://apidocs.kennasecurity.com/reference#list-applications
        try:
            url = self.getEndpoint('/applications')
            res = self.session.get(url)
        except Exception as err:
            res = None
        return True if res is not None else False

    def uploadFile(self, kenna_file: str):
        url = self.getEndpoint(
            '/connectors/{}/data_file?run=true'.format(self.connector)
        )
        logging.info("Connecting to Kenna Endpoint :: " + url)

        # with open(kenna_file, 'rb') as handle:
        c = pycurl.Curl()
        c.setopt(c.URL, url)
        c.setopt(c.POST, 1)
        c.setopt(c.HTTPPOST, [("file", (c.FORM_FILE, kenna_file))])
        c.setopt(pycurl.HTTPHEADER, ['content-type:application/json'])
        c.setopt(pycurl.HTTPHEADER, ['X-Risk-Token:'+self.token])
        c.setopt(c.VERBOSE, 0)
        c.perform()
        c.close()


    def generateData(self, vulnerabilities):
        now = datetime.datetime.strftime(
            datetime.datetime.now(), "%Y-%m-%d-%X"
        )

        findings = []
        vuln_defs = []

        for vulnerability in vulnerabilities:
            findings.append({
                "scanner_type": "codescanning",
                "scanner_identifier": vulnerability.identifier,
                "scanner_score": int(vulnerability.criticality[1]),
                "created_at": now,
                # TODO: get value from GitHub API
                "last_seen_at": now,
                "triage_status": "open",
                "additional_fields": {
                    "line_number": vulnerability.line_number,
                    "source_file": vulnerability.filepath
                }
            })

            vuln_defs.append({
                "scanner_identifier": vulnerability.identifier,
                "scanner_type": "codescanning",
                "cwe_identifiers": ','.join(vulnerability.cwes),
                "name": vulnerability.name,
                "description": vulnerability.description
            })

        data = {
            "skip_autoclose": False,
            "assets": [{
                "url": self.application,
                "tags": [
                    "AppID:CodeQL"
                ],
                "vulns": [],
                "findings": findings
            }],
            "vuln_defs": vuln_defs
        }

        return data

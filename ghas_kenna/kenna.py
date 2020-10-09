
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
        })

    def getEndpoint(self, path: str = ''):
        return self.endpoint + path

    def _buildRequest(self, path: str, params: dict = {}) -> dict:
        res = self.session.get(self.getEndpoint(path), params=params)
        if res.status_code != 200:
            raise Exception()
        return res.json()

    def checkLogin(self) -> bool:
        # https://apidocs.kennasecurity.com/reference#list-applications
        try:
            res = self._buildRequest('/applications')
        except Exception as err:
            res = None
        return True if res is not None else False

    def uploadFile(self, kenna_file: str):
        url = self.getEndpoint(
            '/connectors/{}/data_file?run=true'.format(self.connector)
        )
        logging.info("Connecting to Kenna Endpoint :: " + url)

        with open(kenna_file, 'rb') as handle:
            res = self.session.get(url, files={
                'file': handle
            })
        if res.status_code != 200:
            logging.error("Request Status Code :: " + str(res.status_code))
            # Show content if logging is set to debug
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.error(str(res.text))
            raise Exception("File Upload Request Failed")

        return res.json()

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

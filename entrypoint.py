#!/usr/bin/env python3
import os
import argparse
import requests

parser = argparse.ArgumentParser("advance-security-kenna")

parser.add_argument(
    '-t', '--token',
    default=os.environ.get('TOKEN'),
    help="Kenna Token"
)
parser.add_argument(
    '-e', '--endpoint',
    default=os.environ.get('ENDPOINT', 'https://api.kennasecurity.com')
)
parser.add_argument(
    '-c', '--connector',
    type=int,
    default=os.environ.get('CONNECTOR', 1),
    help="Kenna Connector ID"
)
parser.add_argument(
    '-i', '--input',
    default=os.path.join(os.getcwd(), "../results"),
    help="Folder with SARIF file(s)"
)


arguments = parser.parse_args()


if __name__ == "__main__":
    # Check the endpoint is a valid URL
    SARIF_PATH = os.path.abspath(arguments.input)
    KENNA_URL = arguments.endpoint
    KENNA_URL += "/connectors/" + str(arguments.connector) + "/data_file?run=true"

    print("Kenna Endpoint :: " + KENNA_URL)
    print("SARIF folder :: " + SARIF_PATH)

    if not os.path.exists(SARIF_PATH):
        raise Exception("SARIF folder doesn't exist")

    for filename in os.listdir(SARIF_PATH):
        filepath = os.path.join(SARIF_PATH, filename)
        _, fileext = os.path.splitext(filepath)

        # Ignore everything that isn't a sarif file
        if fileext != ".sarif":
            # print("Ignore file :: " + filepath)
            continue

        print("Process SARIF file :: " + filepath)

        with open(filepath, 'rb') as handle:
            res = requests.post(
                KENNA_URL,
                headers={
                    'content-type': 'application/json',
                    'X-Risk-Token': arguments.token
                },
                files={
                    'file': handle
                }
            )

            if res.status_code != 200:
                raise Exception("Error while posting to the endpoint")

            res_json = res.json()

            print("Successful Upload :: " + str(res_json.get('success')))
            print("Upload date file :: " + str(res_json.get('data_file')))

import logging

import azure.functions as func

# more libs
import os
import requests
import json
# from purviewcli import client
# import sys
# import uuid

from pprint import pformat

from pyapacheatlas.auth import ServicePrincipalAuthentication

logging.basicConfig(level=logging.DEBUG)  # maybe make this an env variable


class CustomPurviewClient:
    def __init__(self, purview_name="", tenant_id="", client_id="", client_secret=""):
        self.catalog_root = f"https://{purview_name}.catalog.purview.azure.com"
        self.scan_root = f"https://{purview_name}.scan.purview.azure.com"

        # query parameters after question mark. ie - http://abc.com/hello?query=world
        self.params = {"api-version": "2018-12-01-preview"}

        self.oauth = ServicePrincipalAuthentication(tenant_id=tenant_id,
                                                    client_id=client_id,
                                                    client_secret=client_secret
                                                    )
        # https://github.com/wjohnson/pyapacheatlas/blob/master/pyapacheatlas/auth/serviceprincipal.py#L50
        self.headers = self.oauth.get_authentication_headers()

    @staticmethod
    def _handle_response(resp):
        """
        https://github.com/wjohnson/pyapacheatlas/blob/master/pyapacheatlas/core/client.py#L45
        Safely handle an Atlas Response and return the results if valid.

        :param Response resp: The response from the request method.

        :return: A dict containing the results.
        :rtype: dict
        """
        try:
            results = json.loads(resp.text)
            resp.raise_for_status()
        except json.JSONDecodeError:
            raise ValueError("Error in parsing: {}".format(resp.text))
        except requests.RequestException:
            raise requests.RequestException(resp.text)

        return results

    def req(self, method, uri, data={}):
        resp = requests.request(method,
                                uri,
                                headers=self.headers,
                                json=data,
                                params=self.params
                                )
        results = self._handle_response(resp)
        return results

    def list_all_classification_rules(self):
        method = "GET"
        endpoint = "classificationrules"
        uri = f"{self.scan_root}/{endpoint}"
        return self.req(method, uri)

    def get_classification_rule(self, rule_name):
        method = "GET"
        endpoint = f"classificationrules/{rule_name}"
        uri = f"{self.scan_root}/{endpoint}"
        return self.req(method, uri)

    def run_scan(self, data_source_name, scan_name, scan_level="Incremental"):
        """
        function to call purview run scan api
        https://docs.microsoft.com/en-us/rest/api/purview/scanningdataplane/scan-result/run-scan
        issue found and was discovered that is now a POST without runId
        https://github.com/tayganr/purviewcli/issues/14

        :param str data_source_name: name of data source in purview collection that hosts the scan
        :param str scan_name: name of scan within the data source
        :param str scan_level: type of scan - Full or Incremental. Default is Incremental

        :return: requests reponse
        :rtype: dict
        """
        method = "POST"
        endpoint = f"datasources/{data_source_name}/scans/{scan_name}/run"
        uri = f"{self.scan_root}/{endpoint}"
        data = {"scanLevel": scan_level}
        return self.req(method, uri, data=data)


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    name = req.params.get('name')
    req_body = None
    if not name:
        try:
            req_body = req.get_json()  # this is how to pass stuff in dynamically
        except ValueError:
            logging.debug("no request body")
        else:
            name = req_body.get('name')

    # log everything
    logging.info(f"request body: {req_body}")

    # constant variables
    # TODO: should come from AKV
    client_id = os.environ.get("CLIENT_ID")
    tenant_id = os.environ.get("TENANT_ID")
    client_secret = os.environ.get("CLIENT_SECRET")

    if req_body:
        config = req_body
    else:
        config = {
            # TODO below should come from body
            "PURVIEW_NAME": "pview-mdp",
            "DATA_SOURCE_NAME": "ADLS-mdp",
            "SCAN_NAME": "Scan-adlsmdp"
        }

    purview_name = config.get("PURVIEW_NAME")
    data_source_name = config.get("DATA_SOURCE_NAME")
    scan_name = config.get("SCAN_NAME")

    custom_client = CustomPurviewClient(purview_name=purview_name,
                                        tenant_id=tenant_id,
                                        client_id=client_id,
                                        client_secret=client_secret
                                        )

    response = custom_client.run_scan(data_source_name,
                                      scan_name,
                                      # default will be Incremental
                                      #   scan_level="Full"
                                      )
    logging.info(response)

    # return response
    if name:
        return func.HttpResponse(f"Hello, {name}. This HTTP triggered function executed successfully.")
    else:
        return func.HttpResponse(
            pformat(
                json.dumps(
                    response
                )
            )
            # "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
            # status_code=200
        )

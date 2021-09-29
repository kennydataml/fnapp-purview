import logging

import azure.functions as func

# more libs
import os
import requests
import json
#from purviewcli import client
import sys
import uuid
from datetime import datetime, timedelta, timezone
import dateutil.parser

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
        except requests.RequestException as e:
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

    def list_scan_history(self, data_source_name, scan_name):
        """
        function to call purview scan result api
        https://docs.microsoft.com/en-us/rest/api/purview/scanningdataplane/scan-result/list-scan-history


        :param str data_source_name: name of data source in purview collection that hosts the scan
        :param str scan_name: name of scan within the data source

        :return: requests reponse
        :rtype: dict
        """
        method = "GET"
        endpoint = f"datasources/{data_source_name}/scans/{scan_name}/runs"
        uri = f"{self.scan_root}/{endpoint}"
        return self.req(method, uri)

    def get_latest_scan(self, data_source_name, scan_name):
        """
        function to get the last purview scan result

        :param str data_source_name: name of data source in purview collection that hosts the scan
        :param str scan_name: name of scan within the data source

        :return: requests reponse
        :rtype: dict
        """
        scan_history = self.list_scan_history(data_source_name, scan_name)
        count = scan_history.get("count")
        if not count:
            return "no scan history count"

        value = scan_history.get("value")
        if not value:
            return "no scan history values"

        latest_scan = max(value, key=lambda item: item["startTime"])
        return latest_scan


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

    latest_scan = custom_client.get_latest_scan(data_source_name, scan_name)
    completed_states = ["Succeeded", "Failed"]

    timezone_offset = -5.0  # Eastern Standard Time (UTC−08:00)
    tzinfo = timezone(timedelta(hours=timezone_offset))
    now = datetime.now(tzinfo)
    # TODO make the max timedelta configurable
    # average scan time is 8 minutes so if it started in the last 10 minutes then we shouldn't start another scan
    max_timedelta = timedelta(minutes=10)

    if latest_scan["status"] in completed_states:
        # checking if the latest scan was started in last 10 minutes
        latest_scan_starttime = dateutil.parser.parse(latest_scan["startTime"])
        latest_scan_timedelta = now - latest_scan_starttime
        logging.info(latest_scan_timedelta)

        if latest_scan_timedelta < max_timedelta:
            # scan was completed in the last 10 minutes
            response = latest_scan
            # logging.info(latest_scan_timedelta)
            # reponse = latest_scan_timedelta
            response["simpleStatus"] = "Complete"
            status_code = 200

        else:
            response = custom_client.run_scan(
                data_source_name,
                scan_name,
                # default will be Incremental
                # scan_level="Full"
            )
            response["description"] = "started a NEW scan"
            response["simpleStatus"] = "Running"
            status_code = 202  # still processing
    else:
        response = latest_scan
        response["description"] = "scan still running"
        response["simpleStatus"] = "Running"
        status_code = 202  # still processing

    logging.info(response)

    # return response
    if name:
        return func.HttpResponse(f"Hello, {name}. This HTTP triggered function executed successfully.")
    else:
        return func.HttpResponse(
            json.dumps(response),
            status_code=status_code
        )

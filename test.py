import importlib
from pprint import pprint

module = importlib.import_module("http-run-pview-scan")

settings = {
    "CLIENT_ID": "",
    "TENANT_ID": "",
    "CLIENT_SECRET": ""
}

client = module.CustomPurviewClient(
    purview_name="pview-mdp",
    tenant_id=settings["TENANT_ID"],
    client_id=settings["CLIENT_ID"],
    client_secret=settings["CLIENT_SECRET"]
)

response = client.get_latest_scan("ADLS-mdp", "scan-adlsmdp")
pprint(response)

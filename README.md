# purview function app
This is a function app wrapped around Purview APIs. This allows us to trigger Purview Scans from ADF.
## debugging azure funtions locally
https://docs.microsoft.com/en-us/azure/azure-functions/functions-develop-vs-code?tabs=python#debugging-functions-locally

When the function runtime starts, you will see the something similar to the following:
```
Http Functions:

        http-run-pview-scan: [GET,POST] http://localhost:7071/api/http-run-pview-scan
```
Just open up the link in your local browser

# authentication to purview
we use pyapacheatlas to get the headers with bearer token: https://github.com/wjohnson/pyapacheatlas/blob/master/pyapacheatlas/auth/serviceprincipal.py#L50

# purview run scan
msft docs are not updated: https://docs.microsoft.com/en-us/rest/api/purview/scanningdataplane/scan-result/run-scan  
issue was open on purviewcli and resolved: https://github.com/tayganr/purviewcli/issues/14  
resolution was the runScan is now a `POST` without runId
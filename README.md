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
## deploying function app
assuming you're using visual studio code, install the Azure Functions extension and ensure your local project shows up. Then hit the cloud button at the top of the menu to deploy to your function app.
Ensure you select Authorization level as `Anonymous`: https://stackoverflow.com/questions/51130370/when-i-am-running-azure-http-trigger-function-i-am-getting-401-unauthorized/53981032
# authentication to purview
we use pyapacheatlas to get the headers with bearer token: https://github.com/wjohnson/pyapacheatlas/blob/master/pyapacheatlas/auth/serviceprincipal.py#L50

# purview run scan
msft docs are not updated: https://docs.microsoft.com/en-us/rest/api/purview/scanningdataplane/scan-result/run-scan  
issue was open on purviewcli and resolved: https://github.com/tayganr/purviewcli/issues/14  
resolution was the runScan is now a `POST` without runId
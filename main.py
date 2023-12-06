"""TODO: module docstring
"""
import re
import sys
import requests

class PlerionError(Exception):
    """TODO: class docstring"""
    def __init__(self, message):
        super().__init__(message)

class PlerionSession(requests.Session):
    """The session handles authentication and allows for request persistence.
    """

    def init_basic_auth(self, api_key: str) -> None:
        """Attach the Authorization header to the session in the correct format.

        As Plerion authentication only requires an API key, which should be
        known by the operator, we only require the population of the
        Authorization header.

        Args:
            api_key (str): The API key to use in all Plerion requests.
        """
        self.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
            }
        )


class PlerionClient:
    """The client abstracts the "heavy-lifting" for constructing requests.
    """

    def __init__(self, api_key: str, debug: bool = False) -> None:
        """Initialize the client with a session, authenticate, and define the endpoint."""
        # Initialize the session.
        self.__session = PlerionSession()

        # Initialize the required authentication mechanism.
        self.__session.init_basic_auth(api_key)

        # Define the base API endpoint to make requests against.
        self.__endpoint = "https://au.api.plerion.com"

        # Configure debug or end-user friendly logging.
        self.__debug = debug

    def __handle_errors(
            self,
            resp: requests.Response,
    ) -> None:
        """Function to handle errors reported by calls to the Plerion API.

        Args:
            requests.Response: The response from the API call.
        """

        # TODO: Replace this w/ the import of a JSON file containing errors and
        #       the "user-friendly" messages.
        error_descriptions = {
            "tenant usage is blocked": (
                "Your tenant's usage has exceeded the authorized limit. To "
                "increase this, please reach out to your administrator to "
                "request an increase in the limit. The usage will be paused "
                "until the limit is increased or reset in the next billing cycle."
            ),
            "unauthorized": (
                "The request requires user authentication. If the request already "
                "included Authorization credentials, then the 401 response indicates "
                "that authorization has been refused for those credentials."
            ),
            "forbidden": (
                "The server understood the request, but is refusing to fulfill it. "
                "Authorization will not fix the issue and the request SHOULD NOT be repeated."
            ),
            "not found": (
                "The server has not found anything matching the Request-URI."
            ),
            "method not allowed": (
                "The method specified in the Request-Line is not allowed for the resource "
                "identified by the Request-URI."
            ),
            "conflict": (
                "The request could not be completed due to a conflict with the current "
                "state of the resource."
            ),
            "too many requests": (
                "Too many requests occurred during the allotted time period and rate "
                "limiting was applied."
            ),
            "internal server error": (
                "The request did not complete due to an internal error on the server side. "
                "The server encountered an unexpected condition which prevented it from "
                "fulfilling the request. "
            ),
            "service unavailable": (
                "The server is currently unable to handle the request due to a temporary "
                "overloading or maintenance of the server."
            )
        }

        # If there are any errors in the response, we don't want to continue.
        if "errors" in resp.json():
            # If debug has been enabled for the PlerionClient, raise an error.
            if self.__debug:
                # Collate all returned error messages into a single string.
                error_messages = ', '.join(list(map(
                    lambda error: error['message'], resp.json()['errors']
                )))
                raise PlerionError(
                    (
                        f"PlerionClient.__request: resp.status_code == \"{resp.status_code}\", "
                        f"errors == \"{error_messages}\"."
                    ),
                )
            # If debug has NOT been enabled, we want more user-friendly error messages.
            error_count = len(resp.json()['errors'])
            print(f"Calling the API has resulted in {error_count} error(s):")
            for error in resp.json()['errors']:
                error_message = error['message']
                error_key = error_message.lower()
                if error_key in error_descriptions:
                    print(f"\t{error_descriptions[error_key]}")
                else:
                    # If no corresponding message exists for the error, report it.
                    print(f"\t~~~UNDOCUMENTED ERROR: {error_message}")
            sys.exit(0)


    # pylint: disable=too-many-arguments
    def __request(
        self,
        method: str,
        path: str,
        version: int = 1,
        params: dict = None,
        data: dict = None,
        headers: dict = None,
    ) -> requests.Response:
        """Basic function to remove this snippet of code out of every other
        function.

        Args:
            method: what type of request is being made (ie - GET, POST, DELETE).

            path: the target API URL.

            version: the API version, default is 1.

            params: any data that needs to be sent through a query string.

            data: any data that needs to be sent through the message body rather
                than through parameters in the query string. Only required for
                POST, PUT, and PATCH.

            headers: any extra headers to add to the base auth headers.

        Returns:
            requests.Response: The response from the API call.
        """
        # There are a specific set of request types that can be executed.
        valid_methods = [
            "GET",
            "OPTIONS",
            "HEAD",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ]
        if method not in valid_methods:
            raise ValueError(
                f"PlerionClient.__request: method must be one of {valid_methods}.",
            )

        req = requests.Request(
            method=method,
            url=f"{self.__endpoint}/v{version}/{path}",
            params=params,
            data=data,
            headers=headers,
        )

        # Execute the request, and return the response.
        prep = self.__session.prepare_request(req)
        resp = self.__session.send(prep)

        # If the status code of the response is 400 or above, handle it.
        if resp.status_code >= 400:
            self.__handle_errors(resp)

        return resp

    # FINDINGS
    # https://au.app.plerion.com/resources/api-reference#tag/FINDINGS

    # Findings are the results of the Plerion Detection Engine (PDE) Detection
    # reporting a finding and rating the severity of the finding as it relates
    # to best practices or a relevant compliance standard. Plerion Findings
    # enable customers to reduce the risk to their environments by continuously
    # highlighting areas for improvement.

    def list_tenant_findings(self, **query_params) -> requests.Response:
        """List findings in a tenant
        https://au.app.plerion.com/resources/api-reference#tag/FINDINGS/operation/listTenantFindings

        Use the list_tenant_findings function to filter findings across the tenant with
        many options from Provider, Service, Detection, Severity, Integration,
        etc. By default all PASSED, FAILED and UNKNOWN findings are returned. To
        list only failed findings filter by statuses=FAILED

        Args:
            **query_params: A list of query params, detailed at the link above.
        """
        # For API calls w/ a large number of params, we're currently not
        # checking them individually.
        valid_params = [
            "ids",
            "detectionIds",
            "regions",
            "assetIds",
            "integrationIds",
            "severityLevels",
            "statuses",
            "resourceTypes",
            "providers",
            "firstObservedStartTime",
            "firstObservedEndTime",
            "sortBy",
            "sortOrder",
            "page",
            "perPage",
        ]

        params = {}
        for param_name in valid_params:
            params[param_name] = query_params.get(param_name)

        headers = {
            "Content-Type": "application/json",
        }

        return self.__request(
            method="GET",
            path="tenant/findings",
            params=params,
            headers=headers,
        )

    # ASSETS
    # https://au.app.plerion.com/resources/api-reference#tag/ASSETS

    # Plerion Assets form the basis upon which all Plerion contextual security is
    # reported. Every unique cloud resource on which Plerion collects information
    # is classified as a single asset on the Plerion platform. A detailed asset
    # view combines various sources of security, compliance, and risk-related
    # metrics to empower customers to make high-impact decisions when evaluating
    # a single asset in relation to their overall cloud environments.

    def list_tenant_assets(self, **query_params) -> requests.Response:
        """List assets in a tenant
        https://au.app.plerion.com/resources/api-reference#tag/ASSETS/operation/listTenantAssets

        Use the list_tenant_assets function to filter assets across the tenant with
        many options from Provider, Service, Severity, Integration, etc. By
        default all assets are returned.

        Args:
            **query_params: A list of query params, detailed at the link above.
        """
        # For API calls w/ a large number of params, we're currently not
        # checking them individually.
        valid_params = [
            "ids",
            "executionIds",
            "regions",
            "integrationIds",
            "severityLevels",
            "secretsLevels",
            "resourceTypes",
            "providers",
            "firstObservedStartTime",
            "firstObservedEndTime",
            "hasAdminPrivileges",
            "hasOverlyPermissivePrivileges",
            "hasKev",
            "hasExploit",
            "isExploitable",
            "isPubliclyExposed",
            "isVulnerable",
            "query",
            "riskScoreGte",
            "sortBy",
            "sortOrder",
            "page",
            "perPage",
        ]

        params = {}
        for param_name in valid_params:
            params[param_name] = query_params.get(param_name)

        headers = {
            "Content-Type": "application/json",
        }

        return self.__request(
            method="GET",
            path="tenant/assets",
            params=params,
            headers=headers,
        )

    # ALERTS
    # https://au.app.plerion.com/resources/api-reference#tag/ALERTS

    # The Plerion Risk Score (PRS) Engine has calculated Alerts that are the
    # highest priority items based on the available information across Identity,
    # Configuration, and Vulnerability Management. Alerts offer the highest value
    # CONTEXT from across the Plerion Platform. Alerts are accompanied by a
    # narrative to guide customers on the overall risk and the recommended
    # remediation steps to take to improve, reduce, or eradicate the identified
    # risk.

    def list_tenant_alerts(self, **query_params) -> requests.Response:
        """List alerts in a tenant
        https://au.app.plerion.com/resources/api-reference#tag/ALERTS/operation/listTenantAlerts

        Use the list_tenant_alerts function to get alerts for the tenant.

        Args:
            **query_params: A list of query params, detailed at the link above.
        """
        # For API calls w/ a large number of params, we're currently not
        # checking them individually.
        valid_params = [
            "ids",
            "executionIds",
            "regions",
            "integrationIds",
            "severityLevels",
            "secretsLevels",
            "resourceTypes",
            "providers",
            "firstObservedStartTime",
            "firstObservedEndTime",
            "hasAdminPrivileges",
            "hasOverlyPermissivePrivileges",
            "hasKev",
            "hasExploit",
            "isExploitable",
            "isPubliclyExposed",
            "isVulnerable",
            "query",
            "riskScoreGte",
            "sortBy",
            "sortOrder",
            "page",
            "perPage",
        ]

        params = {}
        for param_name in valid_params:
            params[param_name] = query_params.get(param_name)

        headers = {
            "Content-Type": "application/json",
        }

        return self.__request(
            method="GET",
            path="tenant/alerts",
            params=params,
            headers=headers,
        )

    # INTEGRATIONS
    # https://au.app.plerion.com/resources/api-reference#tag/INTEGRATIONS

    # Integrations enable customers to connect their own cloud environments to the
    # Plerion platform. Integrations allow for the collection of data from the
    # integrated environment, e.g. Connecting Plerion to your cloud service
    # provider will facilitate Plerion to collect, analyze, and prioritize the
    # most significant risks across your cloud operating environments.

    def list_tenant_integrations(
        self, per_page: int = None, cursor: str = None
    ) -> requests.Response:
        """List inbound integrations in a tenant
        https://au.app.plerion.com/resources/api-reference#tag/INTEGRATIONS/operation/listTenantIntegrations

        Use the list_tenant_integrations function to list all inbound integrations
        that have been added across the tenant.

        Args:
            per_page (int): Specify the batch size of the list. Used for pagination

            cursor (str): Cursor to get next batch of result. Used for pagination
                Example: dGhhbmt5b3UtZm9yLWRlY29kaW5nLWhhdmUtYS1nb29kLWRheTop
        """
        params = {}

        if per_page is not None:
            params["perPage"] = per_page

        if cursor is not None:
            params["cursor"] = cursor

        headers = {
            "Content-Type": "application/json",
        }

        return self.__request(
            method="GET",
            path="tenant/integrations",
            params=params,
            headers=headers,
        )

    # AWS INTEGRATION
    # https://au.app.plerion.com/resources/api-reference#tag/AWS-Integration

    def get_external_id(self) -> requests.Response:
        """Get the external id of the tenant
        https://au.app.plerion.com/resources/api-reference#tag/AWS-Integration/operation/getExternalId

        Use the API to get the external id of the tenant. The external id is
        fixed for a tenant and used for cross-account access to AWS role.
        """
        headers = {
            "Content-Type" : "application/json"
        }

        return self.__request(
            method="GET",
            path="tenant/external-id",
            headers=headers,
        )

    def create_temporary_token(self) -> requests.Response:
        """Generate temporary token for creating AWS integration
        https://au.app.plerion.com/resources/api-reference#tag/AWS-Integration/operation/createTemporaryToken

        Use the API to generate a temporary token required for creating AWS
        integration using CloudFormation template provided by Plerion.
        """
        headers = {
            "Content-Type" : "application/json"
        }

        return self.__request(
            method="GET",
            path="tenant/integrations/token",
            headers=headers,
        )

    def get_cloudformation_template(self, integration_type: str = None) -> requests.Response:
        """Get CloudFormation template
        https://au.app.plerion.com/resources/api-reference#tag/AWS-Integration/operation/getCloudformationTemplate

        Use the API to get the CloudFormation template required for creating /
        updating AWS integrations in Plerion.

        Args:
            integration_type (str): The type of integration for which the
            CloudFormation template is required
        """
        params = {}

        if integration_type is not None:
            params["type"] = integration_type

        headers = {
            "Content-Type" : "application/json"
        }

        return self.__request(
            method="GET",
            path="tenant/cloudformation-templates",
            params=params,
            headers=headers,
        )

    # COMPLIANCE FRAMEWORKS
    # https://au.app.plerion.com/resources/api-reference#tag/COMPLIANCE-FRAMEWORKS

    # Compliance Frameworks help our customers meet their regulatory and
    # compliance obligations, and reduce compliance risk, enabling them to achieve
    # their strategic objectives. Plerion offers customers hundreds of prebuilt
    # detections delivering continuous assurance against industry standards and
    # best practices.

    def list_tenant_compliance_frameworks(self, custom: bool = None) -> requests.Response:
        """List compliance frameworks in a tenant
        https://au.app.plerion.com/resources/api-reference#tag/COMPLIANCE-FRAMEWORKS/operation/listTenantComplianceFrameworks

        Use the list_tenant_compliance_frameworks function to list compliance
        frameworks across the tenant along with the compliance posture for each
        framework as well as the total compliance posture of the tenant.

        Args:
            custom (bool): Filter compliance frameworks based on compliance
            framework type - custom or Plerion managed.
        """
        params = {}

        if custom is not None:
            params["custom"] = custom

        headers = {
            "Content-Type": "application/json",
        }

        return self.__request(
            method="GET",
            path="tenant/compliance-frameworks",
            params=params,
            headers=headers,
        )

    def download_compliance_framework(
        self, integration_id: str, compliance_id: str
    ) -> requests.Response:
        """Download compliance framework report for an integration in a tenant
        https://au.app.plerion.com/resources/api-reference#tag/COMPLIANCE-FRAMEWORKS/operation/downloadComplianceFramework

        Use the download_compliance_framework function to receive a pre-signed
        URL to download a compliance framework summary report for an integration
        within the tenant. This URL will be valid for 1 hour. To download the
        report, use curl or any other tool of your choice.

        Args:
            integration_id (str): UUID of the integration to get.
                Example: c46aa3ee-3d40-4b98-b8ea-e51ed2bf1234

            compliance_id (str): ID of the Compliance Framework to get. This can
            be retrieved using the list_tenant_compliance_frameworks() function.
                Example: CIS-AWSFB-v140
        """
        headers = {
            "Content-Type": "application/json",
        }

        return self.__request(
            method="GET",
            path=(
                f"tenant/integrations/{integration_id}/"
                f"compliance-frameworks/{compliance_id}/download"
            ),
            headers=headers,
        )

    # TENANT USAGE
    # https://au.app.plerion.com/resources/api-reference#tag/TENANT-USAGE

    # Plerion Usage information for the Tenant

    def get_tenant_usage(self, date: str = None) -> requests.Response:
        """Get the usage details of a tenant
        https://au.app.plerion.com/resources/api-reference#tag/TENANT-USAGE/operation/getTenantUsage

        Use the get_tenant_usage function to get the usage details of the
        tenant. The function retrives the total consumed Plerion units for the
        tenant for the specified period and additional information regarding
        whether the limit has been exceeded.

        Args:
            date (str): Specify the date to get usage for the billing interval
            that falls on that date. If you don't include a date parameter, the
            endpoint will default to using the current date. Accepts date time
            in the format yyyy-MM-dd, for example 2023-03-12.
                Example: 2022-02-01
        """
        if date is not None:
            valid_date_format = r"^\d{4}-\d{2}-\d{2}$"
            if not re.match(valid_date_format, date):
                raise ValueError(
                    "PlerionClient.get_tenant_usage: date must be in the"
                    + "format yyyy-MM-dd, for example 2023-04-19.",
                )

        params = {
            "date": date,
        }

        headers = {
            "Content-Type": "application/json",
        }

        return self.__request(
            method="GET",
            path="tenant/compliance-frameworks",
            params=params,
            headers=headers,
        )

    # SHIFT LEFT IAC SCANNING
    # https://au.app.plerion.com/resources/api-reference#tag/Shift-Left-IaC-Scanning

    def iac_scan(self, zip_file_path: str) -> requests.Response:
        """Infrastructure as Code (IaC) Scanning
        https://au.app.plerion.com/resources/api-reference#tag/Shift-Left-IaC-Scanning/paths/~1v1~1tenant~1shiftleft~1iac~1scan/post

        Use the Plerion Shift Left IaC scanning function to scan for security
        vulnerabilities and compliance issues.

        Args:
            zip_file_path (str): The path to the zip file containing the IaC
            templates that you wish to scan.
        """
        with open(zip_file_path, "rb") as file:
            data = file.read()

        params = {
            "artifactName" : f"{zip_file_path}"
        }

        headers = {
            "Content-Type": "application/zip",
        }

        return self.__request(
            method="POST",
            path="tenant/shiftleft/iac/scan",
            params=params,
            headers=headers,
            data=data
        )

    # SHIFT LEFT IAC RESULTS
    # https://au.app.plerion.com/resources/api-reference#tag/Shift-Left-IaC-Results

    def get_all_iac_scans(self, **query_params) -> requests.Response:
        """Get All IaC Scans
        https://au.app.plerion.com/resources/api-reference#tag/Shift-Left-IaC-Results/paths/~1v1~1tenant~1shiftleft~1iac~1scans/get

        Retrieve all the scans for the tenant.

        Args:
            **query_params: A list of query params, detailed at the link above.
        """
        # For API calls w/ a large number of params, we're currently not
        # checking them individually.
        valid_params = [
            "ids",
            "artifactNames",
            "statuses",
            "sortBy",
            "sortOrder",
            "page",
            "perPage",
        ]

        params = {}
        for param_name in valid_params:
            params[param_name] = query_params.get(param_name)

        headers = {
            "Content-Type": "application/json",
        }

        return self.__request(
            method="GET",
            path="tenant/shiftleft/iac/scans",
            params=params,
            headers=headers,
        )

    def get_iac_scan_findings(self, scan_id: str, **query_params) -> requests.Response:
        """Get All Findings
        https://au.app.plerion.com/resources/api-reference#tag/Shift-Left-IaC-Results/paths/~1v1~1tenant~1shiftleft~1iac~1scans~1%7BscanId%7D~1findings/get

        Retrieve all the findings for a scan_id.

        Args:
            scan_id (str): Scan ID to retrieve the results for
            **query_params: A list of query params, detailed at the link above.
        """
        # For API calls w/ a large number of params, we're currently not
        # checking them individually.
        valid_params = [
            "ids",
            "results",
            "detectionIds",
            "types",
            "files",
            "severityLevels",
            "sortBy",
            "sortOrder",
            "page",
            "perPage",
        ]

        params = {}
        for param_name in valid_params:
            params[param_name] = query_params.get(param_name)

        headers = {
            "Content-Type" : "application/json"
        }

        return self.__request(
            method="GET",
            path=f"tenant/shiftleft/iac/scans/{scan_id}/findings",
            params=params,
            headers=headers,
        )

    def get_iac_scan_vulnerabilities(self, scan_id: str, **query_params) -> requests.Response:
        """Get All Vulnerabilities
        https://au.app.plerion.com/resources/api-reference#tag/Shift-Left-IaC-Results/paths/~1v1~1tenant~1shiftleft~1iac~1scans~1%7BscanId%7D~1vulnerabilities/get

        Retrieve all the Vulnerabilities for a scan_id.

        Args:
            scan_id (str): Scan ID to retrieve the results for
            **query_params: A list of query params, detailed at the link above.
        """
        # For API calls w/ a large number of params, we're currently not
        # checking them individually.
        valid_params = [
            "ids",
            "vulnerabilityIds",
            "severitySources",
            "files",
            "hasKevs",
            "hasExploits",
            "severityLevels",
            "sortBy",
            "sortOrder",
            "page",
            "perPage",
        ]

        params = {}
        for param_name in valid_params:
            params[param_name] = query_params.get(param_name)

        headers = {
            "Content-Type" : "application/json"
        }

        return self.__request(
            method="GET",
            path=f"tenant/shiftleft/iac/scans/{scan_id}/vulnerabilities",
            params=params,
            headers=headers,
        )

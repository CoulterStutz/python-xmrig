"""
XMRig API interaction library.

Provides classes and methods to interact with the XMRig miner API for tasks such 
as fetching status, managing configurations, and controlling the mining process.
"""

import requests
from datetime import timedelta


class XMRigAuthorizationError(Exception):
    """
    Exception raised when an authorization error occurs with the XMRig API.

    Attributes:
        message (str): Error message explaining the authorization issue.
    """

    def __init__(self, message="Access token is required but not provided. Please provide a valid access token."):
        """
        Initialize the authorization error.

        Args:
            message (str): Error message. Defaults to a generic authorization error message.
        """
        self.message = message
        super().__init__(self.message)


class XMRigAPI:
    """
    A class to interact with the XMRig miner API.

    Attributes:
        _ip (str): IP address of the XMRig API.
        _port (str): Port of the XMRig API.
        _access_token (str): Access token for authorization.
        _base_url (str): Base URL for the XMRig API.
        _json_rpc_url (str): URL for the json RPC.
        _summary_url (str): URL for the summary endpoint.
        _backends_url (str): URL for the backends endpoint.
        _config_url (str): URL for the config endpoint.
        _summary_response (dict): Response from the summary endpoint.
        _backends_response (dict): Response from the backends endpoint.
        _config_response (dict): Response from the config `GET` endpoint.
        _post_config_response (dict): Response from the config `PUT` endpoint.
        _new_config (dict): Config to update with.
        _headers (dict): Headers for all API/RPC requests.
        _json_rpc_payload (dict): Default payload to send with RPC request.
    """

    def __init__(self, ip: str, port: str, access_token: str = None, tls_enabled: bool = False):
        """
        Initializes the XMRig instance with the provided IP, port, and access token.

        The `ip` can be either an IP address or domain name with its TLD (e.g. `example.com`). The schema is not 
        required and the appropriate one will be chosen based on the `tls_enabled` value.

        Args:
            ip (str): IP address or domain of the XMRig API.
            port (int): Port of the XMRig API.
            access_token (str, optional): Access token for authorization. Defaults to None.
            tls_enabled (bool, optional): TLS status of the miner/API. 
        """
        self._ip = ip
        self._port = port
        self._access_token = access_token
        self._base_url = f"http://{ip}:{port}"
        if tls_enabled == True:
            self._base_url = f"https://{ip}:{port}"
        self._json_rpc_url = f"{self._base_url}/json_rpc"
        self._summary_url = f"{self._base_url}/2/summary"
        self._backends_url = f"{self._base_url}/2/backends"
        self._config_url = f"{self._base_url}/2/config"
        self._summary_response = None
        self._backends_response = None
        self._config_response = None
        self._post_config_response = None
        self._new_config = None
        self._headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Host": f"{self._base_url}",
            "Connection": "keep-alive",
            "Authorization": f"Bearer {self._access_token}"
        }
        self._json_rpc_payload = {
            "method": None,
            "jsonrpc": "2.0",
            "id": 1,
        }
        self.get_all_responses()

    def _set_auth_header(self) -> bool:
        """
        Update the Authorization header for the HTTP requests.

        Returns:
            bool: True if the Authorization header was changed, or False if an error occurred.
        """
        try:
            self._headers['Authorization'] = f"Bearer {self._access_token}"
            return True
        except Exception as e:
            print(f"An error occurred setting the Authorization Header: {e}")
            return False

    def get_summary(self) -> requests.Response.json | bool:
        """
        Fetches the summary data from the XMRig API.

        Returns:
            dict: Parsed JSON response from the summary endpoint, or False if an error occurred.
        """
        try:
            summary_response = requests.get(
                self._summary_url, headers=self._headers)
            if summary_response.status_code == 401:
                raise XMRigAuthorizationError()
            # Raise an HTTPError for bad responses (4xx and 5xx)
            summary_response.raise_for_status()
            return summary_response.json()
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while connecting to {self._summary_url}: {e}")
            return False

    def get_backends(self) -> requests.Response.json | bool:
        """
        Fetches the backends data from the XMRig API.

        Returns:
            dict: Parsed JSON response from the backends endpoint, or False if an error occurred.
        """
        try:
            backends_response = requests.get(
                self._backends_url, headers=self._headers)
            if backends_response.status_code == 401:
                raise XMRigAuthorizationError()
            # Raise an HTTPError for bad responses (4xx and 5xx)
            backends_response.raise_for_status()
            return backends_response.json()
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while connecting to {self._backends_url}: {e}")
            return False

    def get_config(self) -> requests.Response.json | bool:
        """
        Fetches the config data from the XMRig API.

        Returns:
            dict: Parsed JSON response from the config endpoint (GET), or False if an error occurred.
        """
        try:
            config_response = requests.get(
                self._config_url, headers=self._headers)
            if config_response.status_code == 401:
                raise XMRigAuthorizationError()
            # Raise an HTTPError for bad responses (4xx and 5xx)
            config_response.raise_for_status()
            self._config_response = config_response.json()
            return self._config_response
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while connecting to {self._config_url}: {e}")
            return False

    def post_config(self, config: dict) -> bool:
        """
        Updates the config data via the XMRig API.

        Returns:
            bool: True if the config was changed successfully, or False if an error occurred.
        """
        try:
            self._post_config_response = requests.post(
                self._config_url, json=config, headers=self._headers)
            if self._post_config_response.status_code == 401:
                raise XMRigAuthorizationError()
            # Raise an HTTPError for bad responses (4xx and 5xx)
            self._post_config_response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while connecting to {self._config_url}: {e}")
            return False

    def get_all_responses(self) -> bool:
        """
        Retrieves all responses from the API.

        Returns:
            bool: True if successfull, or False if an error occurred.
        """
        try:
            self._summary_response = self.get_summary()
            self._backends_response = self.get_backends()
            if self._access_token != None:
                self._config_response = self.get_config()
            return True
        except Exception as e:
            print(f"An error occurred fetching all the API endpoints: {e}")
            return False

    def pause_miner(self) -> bool:
        """
        Pauses the miner.

        Returns:
            bool: True if the miner was successfully paused, or False if an error occurred.
        """
        try:
            url = f"{self._json_rpc_url}"
            payload = self._json_rpc_payload
            payload["method"] = "pause"
            response = requests.post(url, json=payload, headers=self._headers)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            return False

    def resume_miner(self) -> bool:
        """
        Resumes the miner.

        Returns:
            bool: True if the miner was successfully resumed, or False if an error occurred.
        """
        try:
            url = f"{self._json_rpc_url}"
            payload = self._json_rpc_payload
            payload["method"] = "resume"
            response = requests.post(url, json=payload, headers=self._headers)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            return False

    def stop_miner(self) -> bool:
        """
        Stops the miner.

        Returns:
            bool: True if the miner was successfully stopped, or False if an error occurred.
        """
        try:
            url = f"{self._json_rpc_url}"
            payload = self._json_rpc_payload
            payload["method"] = "stop"
            response = requests.post(url, json=payload, headers=self._headers)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            return False

    # TODO: The `start` json RPC method is not implemented by XMRig yet, use alternative function below until PR 3030 is 
    # TODO: merged see https://github.com/xmrig/xmrig/issues/2826#issuecomment-1146465641
    # TODO: https://github.com/xmrig/xmrig/issues/3220#issuecomment-1450691309 and
    # TODO: https://github.com/xmrig/xmrig/pull/3030 for more infomation.
    def start_miner(self) -> bool:
        """
        Starts the miner.

        Returns:
            bool: True if the miner was successfully started, or False if an error occurred.
        """
        try:
            self.get_config()
            self.post_config()
            return True
        except requests.exceptions.RequestException as e:
            return False

    @property
    def summary(self) -> dict |bool:
        """
        Retrieves the entire cached summary endpoint data.

        Returns:
            dict: Current summary response, or False if not available.
        """
        if self._summary_response:
            return self._summary_response
        return False

    @property
    def backends(self) -> dict | bool:
        """
        Retrieves the entire cached backends endpoint data.

        Returns:
            dict: Current backends response, or False if not available.
        """
        if self._backends_response:
            return self._backends_response
        return False

    @property
    def config(self) -> dict | bool:
        """
        Retrieves the entire cached config endpoint data.

        Returns:
            dict: Current config response, or False if not available.
        """
        if self._config_response:
            return self._config_response
        return False

    @property
    def sum_id(self) -> str | bool:
        """
        Retrieves the cached ID information from the summary data.

        Returns:
            str: ID information, or False if not available.
        """
        if self._summary_response and "id" in self._summary_response:
            return self._summary_response["id"]
        return False

    @property
    def sum_worker_id(self) -> str | bool:
        """
        Retrieves the cached worker ID information from the summary data.

        Returns:
            str: Worker ID information, or False if not available.
        """
        if self._summary_response and "worker_id" in self._summary_response:
            return self._summary_response["worker_id"]
        return False

    @property
    def sum_uptime(self) -> int | bool:
        """
        Retrieves the cached current uptime from the summary data.

        Returns:
            int: Current uptime in seconds, or False if not available.
        """
        if self._summary_response and "uptime" in self._summary_response:
            return self._summary_response["uptime"]
        return False

    @property
    def sum_uptime_readable(self) -> str | bool:
        """
        Retrieves the cached uptime in a human-readable format from the summary data.

        Returns:
            str: Uptime in the format "days, hours:minutes:seconds", or False if not available.
        """
        if self._summary_response and "uptime" in self._summary_response:
            return str(timedelta(seconds=self._summary_response["uptime"]))
        return False

    @property
    def sum_restricted(self) -> bool | None:
        """
        Retrieves the cached current restricted status from the summary data.

        Returns:
            bool: Current restricted status, or None if not available.
        """
        if self._summary_response and "restricted" in self._summary_response:
            return self._summary_response["restricted"]
        return None

    @property
    def sum_resources(self) -> dict | bool:
        """
        Retrieves the cached resources information from the summary data.

        Returns:
            dict: Resources information, or False if not available.
        """
        if self._summary_response and "resources" in self._summary_response:
            return self._summary_response["resources"]
        return False

    @property
    def sum_memory_usage(self) -> dict | bool:
        """
        Retrieves the cached memory usage from the summary data.

        Returns:
            dict: Memory usage information, or False if not available.
        """
        if self._summary_response and "memory" in self._summary_response["resources"]:
            return self._summary_response["resources"]["memory"]
        return False

    @property
    def sum_free_memory(self) -> int | bool:
        """
        Retrieves the cached free memory from the summary data.

        Returns:
            int: Free memory information, or False if not available.
        """
        if self._summary_response and "free" in self._summary_response["resources"]["memory"]:
            return self._summary_response["resources"]["memory"]["free"]
        return False

    @property
    def sum_total_memory(self) -> int | bool:
        """
        Retrieves the cached total memory from the summary data.

        Returns:
            int: Total memory information, or False if not available.
        """
        if self._summary_response and "total" in self._summary_response["resources"]["memory"]:
            return self._summary_response["resources"]["memory"]["total"]
        return False

    @property
    def sum_resident_set_memory(self) -> int | bool:
        """
        Retrieves the cached resident set memory from the summary data.

        Returns:
            int: Resident set memory information, or False if not available.
        """
        if self._summary_response and "resident_set" in self._summary_response["resources"]["memory"]:
            return self._summary_response["resources"]["memory"]["resident_set_memory"]
        return False

    @property
    def sum_load_average(self) -> list | bool:
        """
        Retrieves the cached load average from the summary data.

        Returns:
            list: Load average information, or False if not available.
        """
        if self._summary_response and "load_average" in self._summary_response["resources"]:
            return self._summary_response["resources"]["load_average"]
        return False

    @property
    def sum_hardware_concurrency(self) -> int | bool:
        """
        Retrieves the cached hardware concurrency from the summary data.

        Returns:
            int: Hardware concurrency information, or False if not available.
        """
        if self._summary_response and "hardware_concurrency" in self._summary_response["resources"]:
            return self._summary_response["resources"]["hardware_concurrency"]
        return False

    @property
    def sum_features(self) -> list | bool:
        """
        Retrieves the cached supported features information from the summary data.

        Returns:
            list: Supported features information, or False if not available.
        """
        if self._summary_response and "features" in self._summary_response["resources"]:
            return self._summary_response["resources"]["features"]
        return False

    @property
    def sum_results(self) -> dict | bool:
        """
        Retrieves the cached results information from the summary data.

        Returns:
            dict: Results information, or False if not available.
        """
        if self._summary_response and "results" in self._summary_response:
            return self._summary_response["results"]
        return False

    @property
    def sum_current_difficulty(self) -> int | bool:
        """
        Retrieves the cached current difficulty from the summary data.

        Returns:
            int: Current difficulty, or False if not available.
        """
        if self._summary_response and "results" in self._summary_response:
            return self._summary_response["results"]["diff_current"]
        return False

    @property
    def sum_good_shares(self) -> int | bool:
        """
        Retrieves the cached good shares from the summary data.

        Returns:
            int: Good shares, or False if not available.
        """
        if self._summary_response and "results" in self._summary_response:
            return self._summary_response["results"]["shares_good"]
        return False

    @property
    def sum_total_shares(self) -> int | bool:
        """
        Retrieves the cached total shares from the summary data.

        Returns:
            int: Total shares, or False if not available.
        """
        if self._summary_response and "results" in self._summary_response:
            return self._summary_response["results"]["shares_total"]
        return False

    @property
    def sum_avg_time(self) -> int | bool:
        """
        Retrieves the cached average time information from the summary data.

        Returns:
            int: Average time information, or False if not available.
        """
        if self._summary_response and "results" in self._summary_response:
            return self._summary_response["results"]["avg_time"]
        return False

    @property
    def sum_avg_time_ms(self) -> int | bool:
        """
        Retrieves the cached average time in `ms` information from the summary data.

        Returns:
            int: Average time in `ms` information, or False if not available.
        """
        if self._summary_response and "results" in self._summary_response:
            return self._summary_response["results"]["avg_time_ms"]
        return False

    @property
    def sum_total_hashes(self) -> int | bool:
        """
        Retrieves the cached total number of hashes from the summary data.

        Returns:
            int: Total number of hashes, or False if not available.
        """
        if self._summary_response and "results" in self._summary_response:
            return self._summary_response["results"]["hashes_total"]
        return False

    @property
    def sum_best_results(self) -> list | bool:
        """
        Retrieves the cached best results from the summary data.

        Returns:
            list: Best results, or False if not available.
        """
        if self._summary_response and "results" in self._summary_response:
            return self._summary_response["results"]["best"]
        return False

    @property
    def sum_algorithm(self) -> str | bool:
        """
        Retrieves the cached current mining algorithm from the summary data.

        Returns:
            str: Current mining algorithm, or False if not available.
        """
        if self._summary_response and "algo" in self._summary_response:
            return self._summary_response["algo"]
        return False

    @property
    def sum_connection(self) -> dict | bool:
        """
        Retrieves the cached connection information from the summary data.

        Returns:
            dict: Connection information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            return self._summary_response["connection"]
        return False

    @property
    def sum_pool_info(self) -> str | bool:
        """
        Retrieves the cached pool information from the summary data.

        Returns:
            str: Pool information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            return self._summary_response["connection"]["pool"]
        return False

    @property
    def sum_pool_ip_address(self) -> str | bool:
        """
        Retrieves the cached IP address from the summary data.

        Returns:
            str: IP address, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            return self._summary_response["connection"]["ip"]
        return False

    @property
    def sum_pool_uptime(self) -> int | bool:
        """
        Retrieves the cached pool uptime information from the summary data.

        Returns:
            int: Pool uptime information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            return self._summary_response["connection"]["uptime"]
        return False

    @property
    def sum_pool_uptime_ms(self) -> int | bool:
        """
        Retrieves the cached pool uptime in ms from the summary data.

        Returns:
            int: Pool uptime in ms, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            return self._summary_response["connection"]["uptime_ms"]
        return False

    @property
    def sum_pool_ping(self) -> int | bool:
        """
        Retrieves the cached pool ping information from the summary data.

        Returns:
            int: Pool ping information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            return self._summary_response["connection"]["ping"]
        return False

    @property
    def sum_pool_failures(self) -> int | bool:
        """
        Retrieves the cached pool failures information from the summary data.

        Returns:
            int: Pool failures information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            return self._summary_response["connection"]["failures"]
        return False

    @property
    def sum_pool_tls(self) -> bool | None:
        """
        Retrieves the cached pool tls status from the summary data.

        Returns:
            bool: Pool tls status, or None if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            return self._summary_response["connection"]["tls"]
        return None

    @property
    def sum_pool_tls_fingerprint(self) -> str | bool:
        """
        Retrieves the cached pool tls fingerprint information from the summary data.

        Returns:
            str: Pool tls fingerprint information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            return self._summary_response["connection"]["tls-fingerprint"]
        return False

    @property
    def sum_pool_algo(self) -> str | bool:
        """
        Retrieves the cached pool algorithm information from the summary data.

        Returns:
            str: Pool algorithm information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            return self._summary_response["connection"]["algo"]
        return False

    @property
    def sum_pool_diff(self) -> int | bool:
        """
        Retrieves the cached pool difficulty information from the summary data.

        Returns:
            int: Pool difficulty information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            return self._summary_response["connection"]["diff"]
        return False

    @property
    def sum_pool_accepted_jobs(self) -> int | bool:
        """
        Retrieves the cached number of accepted jobs from the summary data.

        Returns:
            int: Number of accepted jobs, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            return self._summary_response["connection"]["accepted"]
        return False

    @property
    def sum_pool_rejected_jobs(self) -> int | bool:
        """
        Retrieves the cached number of rejected jobs from the summary data.

        Returns:
            int: Number of rejected jobs, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            return self._summary_response["connection"]["rejected"]
        return False

    @property
    def sum_pool_average_time(self) -> int | bool:
        """
        Retrieves the cached pool average time information from the summary data.

        Returns:
            int: Pool average time information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            return self._summary_response["connection"]["avg_time"]
        return False

    @property
    def sum_pool_average_time_ms(self) -> int | bool:
        """
        Retrieves the cached pool average in ms from the summary data.

        Returns:
            int: Pool average in ms, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            return self._summary_response["connection"]["avg_time_ms"]
        return False

    @property
    def sum_pool_total_hashes(self) -> int | bool:
        """
        Retrieves the cached pool total hashes information from the summary data.

        Returns:
            int: Pool total hashes information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            return self._summary_response["connection"]["hashes_total"]
        return False

    @property
    def sum_version(self) -> str | bool:
        """
        Retrieves the cached version information from the summary data.

        Returns:
            str: Version information, or False if not available.
        """
        if self._summary_response and "version" in self._summary_response:
            return self._summary_response["version"]
        return False

    @property
    def sum_kind(self) -> str | bool:
        """
        Retrieves the cached kind information from the summary data.

        Returns:
            str: Kind information, or False if not available.
        """
        if self._summary_response and "kind" in self._summary_response:
            return self._summary_response["kind"]
        return False

    @property
    def sum_ua(self) -> str | bool:
        """
        Retrieves the cached user agent information from the summary data.

        Returns:
            str: User agent information, or False if not available.
        """
        if self._summary_response and "ua" in self._summary_response:
            return self._summary_response["ua"]
        return False

    @property
    def sum_cpu_info(self) -> dict | bool:
        """
        Retrieves the cached CPU information from the summary data.

        Returns:
            dict: CPU information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]
        return False

    @property
    def sum_cpu_brand(self) -> str | bool:
        """
        Retrieves the cached CPU brand information from the summary data.

        Returns:
            str: CPU brand information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["brand"]
        return False

    @property
    def sum_cpu_family(self) -> int | bool:
        """
        Retrieves the cached CPU family information from the summary data.

        Returns:
            int: CPU family information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["family"]
        return False

    @property
    def sum_cpu_model(self) -> int | bool:
        """
        Retrieves the cached CPU model information from the summary data.

        Returns:
            int: CPU model information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["model"]
        return False

    @property
    def sum_cpu_stepping(self) -> int | bool:
        """
        Retrieves the cached CPU stepping information from the summary data.

        Returns:
            int: CPU stepping information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["stepping"]
        return False

    @property
    def sum_cpu_proc_info(self) -> int | bool:
        """
        Retrieves the cached CPU frequency information from the summary data.

        Returns:
            int: CPU frequency information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["proc_info"]
        return False

    @property
    def sum_cpu_aes(self) -> int | bool:
        """
        Retrieves the cached CPU aes information from the summary data.

        Returns:
            int: CPU aes information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["aes"]
        return False

    @property
    def sum_cpu_avx2(self) -> int | bool:
        """
        Retrieves the cached CPU avx2 information from the summary data.

        Returns:
            int: CPU avx2 information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["avx2"]
        return False

    @property
    def sum_cpu_x64(self) -> int | bool:
        """
        Retrieves the cached CPU x64 information from the summary data.

        Returns:
            int: CPU x64 information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["x64"]
        return False

    @property
    def sum_cpu_64_bit(self) -> int | bool:
        """
        Retrieves the cached CPU 64-bit information from the summary data.

        Returns:
            int: CPU 64-bit information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["64_bit"]
        return False

    @property
    def sum_cpu_l2(self) -> int | bool:
        """
        Retrieves the cached CPU l2 cache information from the summary data.

        Returns:
            int: CPU l2 cache information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["l2"]
        return False

    @property
    def sum_cpu_l3(self) -> int | bool:
        """
        Retrieves the cached CPU l3 cache information from the summary data.

        Returns:
            int: CPU l3 cache information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["l3"]
        return False

    @property
    def sum_cpu_cores(self) -> int | bool:
        """
        Retrieves the cached CPU cores information from the summary data.

        Returns:
            int: CPU cores information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["cores"]
        return False

    @property
    def sum_cpu_threads(self) -> int | bool:
        """
        Retrieves the cached CPU threads information from the summary data.

        Returns:
            int: CPU threads information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["threads"]
        return False

    @property
    def sum_cpu_packages(self) -> int | bool:
        """
        Retrieves the cached CPU packages information from the summary data.

        Returns:
            int: CPU packages information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["packages"]
        return False

    @property
    def sum_cpu_nodes(self) -> int | bool:
        """
        Retrieves the cached CPU nodes information from the summary data.

        Returns:
            int: CPU nodes information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["nodes"]
        return False

    @property
    def sum_cpu_backend(self) -> str | bool:
        """
        Retrieves the cached CPU backend information from the summary data.

        Returns:
            str: CPU backend information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["backend"]
        return False

    @property
    def sum_cpu_msr(self) -> str | bool:
        """
        Retrieves the cached CPU msr information from the summary data.

        Returns:
            str: CPU msr information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["msr"]
        return False

    @property
    def sum_cpu_assembly(self) -> str | bool:
        """
        Retrieves the cached CPU assembly information from the summary data.

        Returns:
            str: CPU assembly information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["assembly"]
        return False

    @property
    def sum_cpu_arch(self) -> str | bool:
        """
        Retrieves the cached CPU architecture information from the summary data.

        Returns:
            str: CPU architecture information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["arch"]
        return False

    @property
    def sum_cpu_flags(self) -> list | bool:
        """
        Retrieves the cached CPU flags information from the summary data.

        Returns:
            list: CPU flags information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            return self._summary_response["cpu"]["flags"]
        return False

    @property
    def sum_donate_level(self) -> int | bool:
        """
        Retrieves the cached donation level information from the summary data.

        Returns:
            int: Donation level information, or False if not available.
        """
        if self._summary_response and "donate_level" in self._summary_response:
            return self._summary_response["donate_level"]
        return False

    @property
    def sum_paused(self) -> int | bool:
        """
        Retrieves the cached paused status of the miner from the summary data.

        Returns:
            int: True if the miner is paused, False otherwise, or False if not available.
        """
        if self._summary_response and "paused" in self._summary_response:
            return self._summary_response["paused"]
        return False

    @property
    def sum_algorithms(self) -> list | bool:
        """
        Retrieves the cached algorithms information from the summary data.

        Returns:
            list: Algorithms information, or False if not available.
        """
        if self._summary_response and "algorithms" in self._summary_response:
            return self._summary_response["algorithms"]
        return False

    @property
    def sum_hashrates(self) -> dict | bool:
        """
        Retrieves the cached current hashrates from the summary data.

        Returns:
            dict: Current hashrates, or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            return self._summary_response["hashrate"]
        return False

    @property
    def sum_hashrate_10s(self) -> int | bool:
        """
        Retrieves the cached current hashrate (10s) from the summary data.

        Returns:
            int: Current hashrate (10s), or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            return self._summary_response["hashrate"]["total"][0]
        return False

    @property
    def sum_hashrate_1m(self) -> int | bool:
        """
        Retrieves the cached current hashrate (1m) from the summary data.

        Returns:
            int: Current hashrate (1m), or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            return self._summary_response["hashrate"]["total"][1]
        return False

    @property
    def sum_hashrate_15m(self) -> int | bool:
        """
        Retrieves the cached current hashrate (15m) from the summary data.

        Returns:
            int: Current hashrate (15m), or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            return self._summary_response["hashrate"]["total"][2]
        return False

    @property
    def sum_hashrate_highest(self) -> int | bool:
        """
        Retrieves the cached current hashrate (highest) from the summary data.

        Returns:
            int: Current hashrate (highest), or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            return self._summary_response["hashrate"]["highest"]
        return False

    @property
    def sum_hugepages(self) -> list | bool:
        """
        Retrieves the cached current hugepages from the summary data.

        Returns:
            list: Current hugepages, or False if not available.
        """
        if self._summary_response and "hugepages" in self._summary_response:
            return self._summary_response["hugepages"]
        return False

    # * Data Provided by the backends endpoint
    @property
    def enabled_backends(self) -> list | bool:
        """
        Retrieves the cached currently enabled backends from the backends data.

        Returns:
            list: List of enabled backends, or False if not available.
        """
        types = []
        if self._backends_response:
            for i in self._backends_response:
                if "type" in i and i["enabled"] == True:
                    types.append(i["type"])
            return types
        return False

    @property
    def be_cpu_enabled(self) -> bool | None:
        """
        Retrieves the cached CPU enabled status value from the backends data.

        Returns:
            bool: Bool representing enabled status, or None if not available.
        """
        if self._backends_response and "enabled" in self._backends_response[0]:
            return self._backends_response[0]["enabled"]
        return None

    @property
    def be_cpu_algo(self) -> str | bool:
        """
        Retrieves the cached CPU algorithm information from the backends data.

        Returns:
            str: Bool representing algorithm information, or False if not available.
        """
        if self._backends_response and "algo" in self._backends_response[0]:
            return self._backends_response[0]["algo"]
        return False

    @property
    def be_cpu_profile(self) -> str | bool:
        """
        Retrieves the cached CPU profile information from the backends data.

        Returns:
            str: Bool representing profile information, or False if not available.
        """
        if self._backends_response and "profile" in self._backends_response[0]:
            return self._backends_response[0]["profile"]
        return False

    @property
    def be_cpu_hw_aes(self) -> bool | None:
        """
        Retrieves the cached CPU hw-aes support value from the backends data.

        Returns:
            bool: Bool representing hw-aes support status, or None if not available.
        """
        if self._backends_response and "hw-aes" in self._backends_response[0]:
            return self._backends_response[0]["hw-aes"]
        return None

    @property
    def be_cpu_priority(self) -> int | bool:
        """
        Retrieves the cached CPU  priority from the backends data. 

        Value from 1 (lowest priority) to 5 (highest possible priority). Default 
        value `-1` means XMRig doesn't change threads priority at all,

        Returns:
            int: Int representing mining thread priority, or False if not available.
        """
        if self._backends_response and "priority" in self._backends_response[0]:
            return self._backends_response[0]["priority"]
        return False

    @property
    def be_cpu_msr(self) -> bool | None:
        """
        Retrieves the cached CPU msr information from the backends data.

        Returns:
            bool: Bool representing msr information, or None if not available.
        """
        if self._backends_response and "msr" in self._backends_response[0]:
            return self._backends_response[0]["msr"]
        return None

    @property
    def be_cpu_asm(self) -> str | bool:
        """
        Retrieves the cached CPU asm information from the backends data.

        Returns:
            str: Bool representing asm information, or False if not available.
        """
        if self._backends_response and "asm" in self._backends_response[0]:
            return self._backends_response[0]["asm"]
        return False

    @property
    def be_cpu_argon2_impl(self) -> str | bool:
        """
        Retrieves the cached CPU argon2 implementation information from the backends data.

        Returns:
            str: Bool representing argon2 implementation information, or False if not available.
        """
        if self._backends_response and "argon2-impl" in self._backends_response[0]:
            return self._backends_response[0]["argon2-impl"]
        return False

    @property
    def be_cpu_hugepages(self) -> list | bool:
        """
        Retrieves the cached CPU hugepages information from the backends data.

        Returns:
            list: Bool representing hugepages information, or False if not available.
        """
        if self._backends_response and "hugepages" in self._backends_response[0]:
            return self._backends_response[0]["hugepages"]
        return False

    @property
    def be_cpu_memory(self) -> int | bool:
        """
        Retrieves the cached CPU memory information from the backends data.

        Returns:
            int: Bool representing memory information, or False if not available.
        """
        if self._backends_response and "memory" in self._backends_response[0]:
            return self._backends_response[0]["memory"]
        return False

    @property
    def be_opencl_enabled(self) -> bool | None:
        """
        Retrieves the cached OpenCL enabled information from the backends data.

        Returns:
            bool: Bool representing enabled information, or None if not available.
        """
        if self._backends_response and "enabled" in self._backends_response[1]:
            return self._backends_response[1]["enabled"]
        return None

    @property
    def be_opencl_algo(self) -> str | bool:
        """
        Retrieves the cached OpenCL algorithm information from the backends data.

        Returns:
            str: Bool representing algorithm information, or False if not available.
        """
        if self._backends_response and "algo" in self._backends_response[1]:
            return self._backends_response[1]["algo"]
        return False

    @property
    def be_opencl_profile(self) -> str | bool:
        """
        Retrieves the cached OpenCL profile information from the backends data.

        Returns:
            str: Bool representing profile information, or False if not available.
        """
        if self._backends_response and "profile" in self._backends_response[1]:
            return self._backends_response[1]["profile"]
        return False

    @property
    def be_opencl_platform(self) -> str | bool:
        """
        Retrieves the cached OpenCL platform information from the backends data.

        Returns:
            str: Bool representing platform information, or False if not available.
        """
        if self._backends_response and "platform" in self._backends_response[1]:
            return self._backends_response[1]["platform"]
        return False

    @property
    def be_cuda_type(self) -> str | bool:
        """
        Retrieves the cached Cuda current type info from the backends data.

        Returns:
            str: Current type info, or False if not available.
        """
        if self._backends_response and "type" in self._backends_response[2]:
            return self._backends_response[2]["type"]
        return False

    @property
    def be_cuda_enabled(self) -> bool | None:
        """
        Retrieves the cached Cuda current enabled info from the backends data.

        Returns:
            bool: Current enabled info, or None if not available.
        """
        if self._backends_response and "enabled" in self._backends_response[2]:
            return self._backends_response[2]["enabled"]
        return None

    @property
    def be_cuda_algo(self) -> str | bool:
        """
        Retrieves the cached Cuda algorithm information from the backends data.

        Returns:
            str: Bool representing algorithm information, or False if not available.
        """
        if self._backends_response and "algo" in self._backends_response[2]:
            return self._backends_response[2]["algo"]
        return False

    @property
    def be_cuda_profile(self) -> str | bool:
        """
        Retrieves the cached Cuda profile information from the backends data.

        Returns:
            str: Bool representing profile information, or False if not available.
        """
        if self._backends_response and "profile" in self._backends_response[2]:
            return self._backends_response[2]["profile"]
        return False

    @property
    def be_cuda_versions(self) -> dict | bool:
        """
        Retrieves the cached Cuda versions information from the backends data.

        Returns:
            dict: Bool representing versions information, or False if not available.
        """
        if self._backends_response and "versions" in self._backends_response[2]:
            return self._backends_response[2]["versions"]
        return False

    @property
    def be_cuda_runtime(self) -> str | bool:
        """
        Retrieves the cached Cuda runtime information from the backends data.

        Returns:
           str: Bool representing cuda runtime information, or False if not available.
        """
        if self._backends_response and "cuda-runtime" in self._backends_response[2]:
            return self._backends_response[2]["versions"]["cuda-runtime"]
        return False

    @property
    def be_cuda_driver(self) -> str | bool:
        """
        Retrieves the cached Cuda driver information from the backends data.

        Returns:
            str: Bool representing cuda driver information, or False if not available.
        """
        if self._backends_response and "cuda-driver" in self._backends_response[2]:
            return self._backends_response[2]["versions"]["cuda-driver"]
        return False

    @property
    def be_cuda_plugin(self) -> str | bool:
        """
        Retrieves the cached Cuda plugin information from the backends data.

        Returns:
            str: Bool representing cuda plugin information, or False if not available.
        """
        if self._backends_response and "plugin" in self._backends_response[2]:
            return self._backends_response[2]["versions"]["plugin"]
        return False

    @property
    def be_cuda_hashrate(self) -> list | bool:
        """
        Retrieves the cached Cuda current hashrate info from the backends data.

        Returns:
            list: Current hashrate info, or False if not available.
        """
        if self._backends_response and "hashrate" in self._backends_response[2]:
            return self._backends_response[2]["hashrate"]
        return False

    @property
    def be_cuda_hashrate_10s(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (10s) info from the backends data.

        Returns:
           int: Current hashrate (10s) info, or False if not available.
        """
        if self._backends_response and "hashrate" in self._backends_response[2]:
            return self._backends_response[2]["hashrate"][0]
        return False

    @property
    def be_cuda_hashrate_1m(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (1m) info from the backends data.

        Returns:
            int: Current hashrate (1m) info, or False if not available.
        """
        if self._backends_response and "hashrate" in self._backends_response[2]:
            return self._backends_response[2]["hashrate"][1]
        return False

    @property
    def be_cuda_hashrate_15m(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (15m) info from the backends data.

        Returns:
            int: Current hashrate (15m) info, or False if not available.
        """
        if self._backends_response and "hashrate" in self._backends_response[2]:
            return self._backends_response[2]["hashrate"][2]
        return False

    @property
    def be_cuda_threads(self) -> dict | bool:
        """
        Retrieves the cached Cuda current threads info from the backends data.

        Returns:
            dict: Current threads info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            return self._backends_response[2]["threads"][0]
        return False

    @property
    def be_cuda_threads_index(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads index info from the backends data.

        Returns:
            int: Current threads index info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            return self._backends_response[2]["threads"][0]["index"]
        return False

    @property
    def be_cuda_threads_amount(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads amount info from the backends data.

        Returns:
            int: Current threads amount info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            return self._backends_response[2]["threads"][0]["threads"]
        return False

    @property
    def be_cuda_threads_blocks(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads blocks info from the backends data.

        Returns:
            int: Current threads blocks info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            return self._backends_response[2]["threads"][0]["blocks"]
        return False

    @property
    def be_cuda_threads_bfactor(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads bfactor info from the backends data.

        Returns:
            int: Current threads bfactor info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            return self._backends_response[2]["threads"][0]["bfactor"]
        return False

    @property
    def be_cuda_threads_bsleep(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads bsleep info from the backends data.

        Returns:
            int: Current threads bsleep info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            return self._backends_response[2]["threads"][0]["bsleep"]
        return False

    @property
    def be_cuda_threads_affinity(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads affinity info from the backends data.

        Returns:
            int: Current threads affinity info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            return self._backends_response[2]["threads"][0]["affinity"]
        return False

    @property
    def be_cuda_threads_dataset_host(self) -> bool | None:
        """
        Retrieves the cached Cuda current threads dataset host info from the backends data.

        Returns:
            bool: Current threads dataset host info, or None if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            return self._backends_response[2]["threads"][0]["dataset_host"]
        return None

    @property
    def be_cuda_threads_hashrates(self) -> list | bool:
        """
        Retrieves the cached Cuda current hashrates (10s/1m/15m) from the summary data.

        Returns:
            list: Current hashrates, or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            return self._backends_response[2]["threads"][0]["hashrate"]
        return False

    @property
    def be_cuda_threads_hashrate_10s(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (10s) from the summary data.

        Returns:
            int: Current hashrate (10s), or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            return self._backends_response[2]["threads"][0]["hashrate"][0]
        return False

    @property
    def be_cuda_threads_hashrate_1m(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (1m) from the summary data.

        Returns:
            int: Current hashrate (1m), or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            return self._backends_response[2]["threads"][0]["hashrate"][1]
        return False

    @property
    def be_cuda_threads_hashrate_15m(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (15m) from the summary data.

        Returns:
            int: Current hashrate (15m), or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            return self._backends_response[2]["threads"][0]["hashrate"][2]
        return False

    @property
    def be_cuda_threads_name(self) -> str | bool:
        """
        Retrieves the cached Cuda current threads name info from the backends data.

        Returns:
            str: Current threads name info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            return self._backends_response[2]["threads"][0]["name"]
        return False

    @property
    def be_cuda_threads_bus_id(self) -> str | bool:
        """
        Retrieves the cached Cuda current threads bus ID info from the backends data.

        Returns:
            str: Current threads bus ID info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            return self._backends_response[2]["threads"][0]["bus_id"]
        return False

    @property
    def be_cuda_threads_smx(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads smx info from the backends data.

        Returns:
            int: Current threads smx info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            return self._backends_response[2]["threads"][0]["smx"]
        return False

    @property
    def be_cuda_threads_arch(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads arch info from the backends data.

        Returns:
            int: Current threads arch info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            return self._backends_response[2]["threads"][0]["arch"]
        return False

    @property
    def be_cuda_threads_global_mem(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads global mem info from the backends data.

        Returns:
            int: Current threads global mem info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            return self._backends_response[2]["threads"][0]["global_mem"]
        return False

    @property
    def be_cuda_threads_clock(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads clock info from the backends data.

        Returns:
            int: Current threads clock info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            return self._backends_response[2]["threads"][0]["clock"]
        return False

    @property
    def be_cuda_threads_memory_clock(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads memory clock info from the backends data.

        Returns:
            int: Current threads memory_clock info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            return self._backends_response[2]["threads"][0]["memory_clock"]
        return False

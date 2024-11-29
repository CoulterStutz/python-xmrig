"""
XMRig API interaction library.

Provides classes and methods to interact with the XMRig miner API for tasks such 
as fetching status, managing configurations, and controlling the mining process.
"""

import requests, logging
from datetime import timedelta

log = logging.getLogger("XMRigAPI")

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
        self.update_all_responses()
        log.info("XMRigAPI initialized.")

    def _set_auth_header(self) -> bool:
        """
        Update the Authorization header for the HTTP requests.

        Returns:
            bool: True if the Authorization header was changed, or False if an error occurred.
        """
        try:
            self._headers['Authorization'] = f"Bearer {self._access_token}"
            log.info(f"Authorization header successfully changed.")
            return True
        except Exception as e:
            log.error(f"An error occurred setting the Authorization Header: {e}")
            return False

    def update_summary(self) -> bool:
        """
        Updates the cached summary data from the XMRig API.

        Returns:
            dict: True if the cached data is successfully updated or False if an error occurred.
        """
        try:
            summary_response = requests.get(
                self._summary_url, headers=self._headers)
            if summary_response.status_code == 401:
                raise XMRigAuthorizationError()
            # Raise an HTTPError for bad responses (4xx and 5xx)
            summary_response.raise_for_status()
            self._summary_response = summary_response.json()
            log.info(f"Summary endpoint successfully fetched.")
            return True
        except requests.exceptions.RequestException as e:
            log.error(f"An error occurred while connecting to {self._summary_url}: {e}")
            return False

    def update_backends(self) -> bool:
        """
        Updates the cached backends data from the XMRig API.

        Returns:
            dict: True if the cached data is successfully updated or False if an error occurred.
        """
        try:
            backends_response = requests.get(
                self._backends_url, headers=self._headers)
            if backends_response.status_code == 401:
                raise XMRigAuthorizationError()
            # Raise an HTTPError for bad responses (4xx and 5xx)
            backends_response.raise_for_status()
            self._backends_response = backends_response.json()
            log.info(f"Backends endpoint successfully fetched.")
            return True
        except requests.exceptions.RequestException as e:
            log.error(f"An error occurred while connecting to {self._backends_url}: {e}")
            return False

    def update_config(self) -> bool:
        """
        Updates the cached config data from the XMRig API.

        Returns:
            dict: True if the cached data is successfully updated, or False if an error occurred.
        """
        try:
            config_response = requests.get(
                self._config_url, headers=self._headers)
            if config_response.status_code == 401:
                raise XMRigAuthorizationError()
            # Raise an HTTPError for bad responses (4xx and 5xx)
            config_response.raise_for_status()
            self._config_response = config_response.json()
            log.info(f"Config endpoint successfully fetched.")
            return True
        except requests.exceptions.RequestException as e:
            log.error(f"An error occurred while connecting to {self._config_url}: {e}")
            return False

    def post_config(self, config: dict) -> bool:
        """
        Updates the miners config data via the XMRig API.

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
            log.info(f"Config endpoint successfully updated.")
            return True
        except requests.exceptions.RequestException as e:
            log.error(f"An error occurred while connecting to {self._config_url}: {e}")
            return False

    def update_all_responses(self) -> bool:
        """
        Retrieves all responses from the API.

        Returns:
            bool: True if successfull, or False if an error occurred.
        """
        try:
            self.update_summary()
            self.update_backends()
            if self._access_token != None:
                self.update_config()
            log.info(f"All endpoints successfully fetched.")
            return True
        except Exception as e:
            log.error(f"An error occurred fetching all the API endpoints: {e}")
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
            log.info(f"Miner successfully paused.")
            return True
        except requests.exceptions.RequestException as e:
            log.error(f"An error occurred pausing the miner: {e}")
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
            log.info(f"Miner successfully resumed.")
            return True
        except requests.exceptions.RequestException as e:
            log.error(f"An error occurred restarting the miner: {e}")
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
            log.info(f"Miner successfully stopped.")
            return True
        except requests.exceptions.RequestException as e:
            log.error(f"An error occurred stopping the miner: {e}")
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
            self.update_config()
            self.post_config()
            log.info(f"Miner successfully started.")
            return True
        except requests.exceptions.RequestException as e:
            log.error(f"An error occurred starting the miner: {e}")
            return False

    @property
    def summary(self) -> dict |bool:
        """
        Retrieves the entire cached summary endpoint data.

        Returns:
            dict: Current summary response, or False if not available.
        """
        if self._summary_response:
            log.debug(self._summary_response)
            return self._summary_response
        log.error(f"An error occurred fetching the cached summary data.")
        return False

    @property
    def backends(self) -> dict | bool:
        """
        Retrieves the entire cached backends endpoint data.

        Returns:
            dict: Current backends response, or False if not available.
        """
        if self._backends_response:
            log.debug(self._backends_response)
            return self._backends_response
        log.error(f"An error occurred fetching the cached backends data.")
        return False

    @property
    def config(self) -> dict | bool:
        """
        Retrieves the entire cached config endpoint data.

        Returns:
            dict: Current config response, or False if not available.
        """
        if self._config_response:
            log.debug(self._config_response)
            return self._config_response
        log.error(f"An error occurred fetching the cached config data.")
        return False

    @property
    def sum_id(self) -> str | bool:
        """
        Retrieves the cached ID information from the summary data.

        Returns:
            str: ID information, or False if not available.
        """
        if self._summary_response and "id" in self._summary_response:
            log.debug(self._summary_response["id"])
            return self._summary_response["id"]
        log.error(f"An error occurred fetching the cached ID information data.")
        return False

    @property
    def sum_worker_id(self) -> str | bool:
        """
        Retrieves the cached worker ID information from the summary data.

        Returns:
            str: Worker ID information, or False if not available.
        """
        if self._summary_response and "worker_id" in self._summary_response:
            log.debug(self._summary_response["worker_id"])
            return self._summary_response["worker_id"]
        log.error(f"An error occurred fetching the cached worker ID information data.")
        return False

    @property
    def sum_uptime(self) -> int | bool:
        """
        Retrieves the cached current uptime from the summary data.

        Returns:
            int: Current uptime in seconds, or False if not available.
        """
        if self._summary_response and "uptime" in self._summary_response:
            log.debug(self._summary_response["uptime"])
            return self._summary_response["uptime"]
        log.error(f"An error occurred fetching the cached current uptime data.")
        return False

    @property
    def sum_uptime_readable(self) -> str | bool:
        """
        Retrieves the cached uptime in a human-readable format from the summary data.

        Returns:
            str: Uptime in the format "days, hours:minutes:seconds", or False if not available.
        """
        if self._summary_response and "uptime" in self._summary_response:
            log.debug(str(timedelta(seconds=self._summary_response["uptime"])))
            return str(timedelta(seconds=self._summary_response["uptime"]))
        log.error(f"An error occurred fetching the cached current uptime in a human-readable format data.")
        return False

    @property
    def sum_restricted(self) -> bool | None:
        """
        Retrieves the cached current restricted status from the summary data.

        Returns:
            bool: Current restricted status, or None if not available.
        """
        if self._summary_response and "restricted" in self._summary_response:
            log.debug(self._summary_response["restricted"])
            return self._summary_response["restricted"]
        log.error(f"An error occurred fetching the cached restricted status data.")
        return None

    @property
    def sum_resources(self) -> dict | bool:
        """
        Retrieves the cached resources information from the summary data.

        Returns:
            dict: Resources information, or False if not available.
        """
        if self._summary_response and "resources" in self._summary_response:
            log.debug(self._summary_response["resources"])
            return self._summary_response["resources"]
        log.error(f"An error occurred fetching the cached resources data.")
        return False

    @property
    def sum_memory_usage(self) -> dict | bool:
        """
        Retrieves the cached memory usage from the summary data.

        Returns:
            dict: Memory usage information, or False if not available.
        """
        if self._summary_response and "memory" in self._summary_response["resources"]:
            log.debug(self._summary_response["resources"]["memory"])
            return self._summary_response["resources"]["memory"]
        log.error(f"An error occurred fetching the cached memory usage data.")
        return False

    @property
    def sum_free_memory(self) -> int | bool:
        """
        Retrieves the cached free memory from the summary data.

        Returns:
            int: Free memory information, or False if not available.
        """
        if self._summary_response and "free" in self._summary_response["resources"]["memory"]:
            log.debug(self._summary_response["resources"]["memory"]["free"])
            return self._summary_response["resources"]["memory"]["free"]
        log.error(f"An error occurred fetching the cached free memory data.")
        return False

    @property
    def sum_total_memory(self) -> int | bool:
        """
        Retrieves the cached total memory from the summary data.

        Returns:
            int: Total memory information, or False if not available.
        """
        if self._summary_response and "total" in self._summary_response["resources"]["memory"]:
            log.debug(self._summary_response["resources"]["memory"]["total"])
            return self._summary_response["resources"]["memory"]["total"]
        log.error(f"An error occurred fetching the cached total memory data.")
        return False

    @property
    def sum_resident_set_memory(self) -> int | bool:
        """
        Retrieves the cached resident set memory from the summary data.

        Returns:
            int: Resident set memory information, or False if not available.
        """
        if self._summary_response and "resident_set" in self._summary_response["resources"]["memory"]:
            log.debug(self._summary_response["resources"]["memory"]["resident_set_memory"])
            return self._summary_response["resources"]["memory"]["resident_set_memory"]
        log.error(f"An error occurred fetching the cached resident set memory data.")
        return False

    @property
    def sum_load_average(self) -> list | bool:
        """
        Retrieves the cached load average from the summary data.

        Returns:
            list: Load average information, or False if not available.
        """
        if self._summary_response and "load_average" in self._summary_response["resources"]:
            log.debug(self._summary_response["resources"]["load_average"])
            return self._summary_response["resources"]["load_average"]
        log.error(f"An error occurred fetching the cached load average data.")
        return False

    @property
    def sum_hardware_concurrency(self) -> int | bool:
        """
        Retrieves the cached hardware concurrency from the summary data.

        Returns:
            int: Hardware concurrency information, or False if not available.
        """
        if self._summary_response and "hardware_concurrency" in self._summary_response["resources"]:
            log.debug(self._summary_response["resources"]["hardware_concurrency"])
            return self._summary_response["resources"]["hardware_concurrency"]
        log.error(f"An error occurred fetching the cached hardware concurrency data.")
        return False

    @property
    def sum_features(self) -> list | bool:
        """
        Retrieves the cached supported features information from the summary data.

        Returns:
            list: Supported features information, or False if not available.
        """
        if self._summary_response and "features" in self._summary_response["resources"]:
            log.debug(self._summary_response["resources"]["features"])
            return self._summary_response["resources"]["features"]
        log.error(f"An error occurred fetching the cached features data.")
        return False

    @property
    def sum_results(self) -> dict | bool:
        """
        Retrieves the cached results information from the summary data.

        Returns:
            dict: Results information, or False if not available.
        """
        if self._summary_response and "results" in self._summary_response:
            log.debug(self._summary_response["results"])
            return self._summary_response["results"]
        log.error(f"An error occurred fetching the cached results data.")
        return False

    @property
    def sum_current_difficulty(self) -> int | bool:
        """
        Retrieves the cached current difficulty from the summary data.

        Returns:
            int: Current difficulty, or False if not available.
        """
        if self._summary_response and "results" in self._summary_response:
            log.debug(self._summary_response["results"]["diff_current"])
            return self._summary_response["results"]["diff_current"]
        log.error(f"An error occurred fetching the cached current difficulty data.")
        return False

    @property
    def sum_good_shares(self) -> int | bool:
        """
        Retrieves the cached good shares from the summary data.

        Returns:
            int: Good shares, or False if not available.
        """
        if self._summary_response and "results" in self._summary_response:
            log.debug(self._summary_response["results"]["shares_good"])
            return self._summary_response["results"]["shares_good"]
        log.error(f"An error occurred fetching the cached good shares data.")
        return False

    @property
    def sum_total_shares(self) -> int | bool:
        """
        Retrieves the cached total shares from the summary data.

        Returns:
            int: Total shares, or False if not available.
        """
        if self._summary_response and "results" in self._summary_response:
            log.debug(self._summary_response["results"]["shares_total"])
            return self._summary_response["results"]["shares_total"]
        log.error(f"An error occurred fetching the cached total shares data.")
        return False

    @property
    def sum_avg_time(self) -> int | bool:
        """
        Retrieves the cached average time information from the summary data.

        Returns:
            int: Average time information, or False if not available.
        """
        if self._summary_response and "results" in self._summary_response:
            log.debug(self._summary_response["results"]["avg_time"])
            return self._summary_response["results"]["avg_time"]
        log.error(f"An error occurred fetching the cached average time data.")
        return False

    @property
    def sum_avg_time_ms(self) -> int | bool:
        """
        Retrieves the cached average time in `ms` information from the summary data.

        Returns:
            int: Average time in `ms` information, or False if not available.
        """
        if self._summary_response and "results" in self._summary_response:
            log.debug(self._summary_response["results"]["avg_time_ms"])
            return self._summary_response["results"]["avg_time_ms"]
        log.error(f"An error occurred fetching the cached average time in `ms` data.")
        return False

    @property
    def sum_total_hashes(self) -> int | bool:
        """
        Retrieves the cached total number of hashes from the summary data.

        Returns:
            int: Total number of hashes, or False if not available.
        """
        if self._summary_response and "results" in self._summary_response:
            log.debug(self._summary_response["results"]["hashes_total"])
            return self._summary_response["results"]["hashes_total"]
        log.error(f"An error occurred fetching the cached total hashes data.")
        return False

    @property
    def sum_best_results(self) -> list | bool:
        """
        Retrieves the cached best results from the summary data.

        Returns:
            list: Best results, or False if not available.
        """
        if self._summary_response and "results" in self._summary_response:
            log.debug(self._summary_response["results"]["best"])
            return self._summary_response["results"]["best"]
        log.error(f"An error occurred fetching the cached best results data.")
        return False

    @property
    def sum_algorithm(self) -> str | bool:
        """
        Retrieves the cached current mining algorithm from the summary data.

        Returns:
            str: Current mining algorithm, or False if not available.
        """
        if self._summary_response and "algo" in self._summary_response:
            log.debug(self._summary_response["algo"])
            return self._summary_response["algo"]
        log.error(f"An error occurred fetching the cached current mining alogorithm data.")
        return False

    @property
    def sum_connection(self) -> dict | bool:
        """
        Retrieves the cached connection information from the summary data.

        Returns:
            dict: Connection information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            log.debug(self._summary_response["connection"])
            return self._summary_response["connection"]
        log.error(f"An error occurred fetching the cached connection data.")
        return False

    @property
    def sum_pool_info(self) -> str | bool:
        """
        Retrieves the cached pool information from the summary data.

        Returns:
            str: Pool information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            log.debug(self._summary_response["connection"]["pool"])
            return self._summary_response["connection"]["pool"]
        log.error(f"An error occurred fetching the cached pool information data.")
        return False

    @property
    def sum_pool_ip_address(self) -> str | bool:
        """
        Retrieves the cached IP address from the summary data.

        Returns:
            str: IP address, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            log.debug(self._summary_response["connection"]["ip"])
            return self._summary_response["connection"]["ip"]
        log.error(f"An error occurred fetching the cached IP address data.")
        return False

    @property
    def sum_pool_uptime(self) -> int | bool:
        """
        Retrieves the cached pool uptime information from the summary data.

        Returns:
            int: Pool uptime information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            log.debug(self._summary_response["connection"]["uptime"])
            return self._summary_response["connection"]["uptime"]
        log.error(f"An error occurred fetching the cached pool uptime data.")
        return False

    @property
    def sum_pool_uptime_ms(self) -> int | bool:
        """
        Retrieves the cached pool uptime in ms from the summary data.

        Returns:
            int: Pool uptime in ms, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            log.debug(self._summary_response["connection"]["uptime_ms"])
            return self._summary_response["connection"]["uptime_ms"]
        log.error(f"An error occurred fetching the cached pool uptime in `ms` data.")
        return False

    @property
    def sum_pool_ping(self) -> int | bool:
        """
        Retrieves the cached pool ping information from the summary data.

        Returns:
            int: Pool ping information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            log.debug(self._summary_response["connection"]["ping"])
            return self._summary_response["connection"]["ping"]
        log.error(f"An error occurred fetching the cached pool ping data.")
        return False

    @property
    def sum_pool_failures(self) -> int | bool:
        """
        Retrieves the cached pool failures information from the summary data.

        Returns:
            int: Pool failures information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            log.debug(self._summary_response["connection"]["failures"])
            return self._summary_response["connection"]["failures"]
        log.error(f"An error occurred fetching the cached pool failures data.")
        return False

    @property
    def sum_pool_tls(self) -> bool | None:
        """
        Retrieves the cached pool tls status from the summary data.

        Returns:
            bool: Pool tls status, or None if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            log.debug(self._summary_response["connection"]["tls"])
            return self._summary_response["connection"]["tls"]
        log.error(f"An error occurred fetching the cached pool tls data.")
        return None

    @property
    def sum_pool_tls_fingerprint(self) -> str | bool:
        """
        Retrieves the cached pool tls fingerprint information from the summary data.

        Returns:
            str: Pool tls fingerprint information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            log.debug(self._summary_response["connection"]["tls-fingerprint"])
            return self._summary_response["connection"]["tls-fingerprint"]
        log.error(f"An error occurred fetching the cached pool tls fingerprint data.")
        return False

    @property
    def sum_pool_algo(self) -> str | bool:
        """
        Retrieves the cached pool algorithm information from the summary data.

        Returns:
            str: Pool algorithm information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            log.debug(self._summary_response["connection"]["algo"])
            return self._summary_response["connection"]["algo"]
        log.error(f"An error occurred fetching the cached pool algorithm data.")
        return False

    @property
    def sum_pool_diff(self) -> int | bool:
        """
        Retrieves the cached pool difficulty information from the summary data.

        Returns:
            int: Pool difficulty information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            log.debug(self._summary_response["connection"]["diff"])
            return self._summary_response["connection"]["diff"]
        log.error(f"An error occurred fetching the cached pool difficulty data.")
        return False

    @property
    def sum_pool_accepted_jobs(self) -> int | bool:
        """
        Retrieves the cached number of accepted jobs from the summary data.

        Returns:
            int: Number of accepted jobs, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            log.debug(self._summary_response["connection"]["accepted"])
            return self._summary_response["connection"]["accepted"]
        log.error(f"An error occurred fetching the cached pool accepted jobs data.")
        return False

    @property
    def sum_pool_rejected_jobs(self) -> int | bool:
        """
        Retrieves the cached number of rejected jobs from the summary data.

        Returns:
            int: Number of rejected jobs, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            log.debug(self._summary_response["connection"]["rejected"])
            return self._summary_response["connection"]["rejected"]
        log.error(f"An error occurred fetching the cached pool rejected jobs data.")
        return False

    @property
    def sum_pool_average_time(self) -> int | bool:
        """
        Retrieves the cached pool average time information from the summary data.

        Returns:
            int: Pool average time information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            log.debug(self._summary_response["connection"]["avg_time"])
            return self._summary_response["connection"]["avg_time"]
        log.error(f"An error occurred fetching the cached pool average time data.")
        return False

    @property
    def sum_pool_average_time_ms(self) -> int | bool:
        """
        Retrieves the cached pool average in ms from the summary data.

        Returns:
            int: Pool average in ms, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            log.debug(self._summary_response["connection"]["avg_time_ms"])
            return self._summary_response["connection"]["avg_time_ms"]
        log.error(f"An error occurred fetching the cached pool average time in `ms` data.")
        return False

    @property
    def sum_pool_total_hashes(self) -> int | bool:
        """
        Retrieves the cached pool total hashes information from the summary data.

        Returns:
            int: Pool total hashes information, or False if not available.
        """
        if self._summary_response and "connection" in self._summary_response:
            log.debug(self._summary_response["connection"]["hashes_total"])
            return self._summary_response["connection"]["hashes_total"]
        log.error(f"An error occurred fetching the cached pool total hashes data.")
        return False

    @property
    def sum_version(self) -> str | bool:
        """
        Retrieves the cached version information from the summary data.

        Returns:
            str: Version information, or False if not available.
        """
        if self._summary_response and "version" in self._summary_response:
            log.debug(self._summary_response["version"])
            return self._summary_response["version"]
        log.error(f"An error occurred fetching the cached version data.")
        return False

    @property
    def sum_kind(self) -> str | bool:
        """
        Retrieves the cached kind information from the summary data.

        Returns:
            str: Kind information, or False if not available.
        """
        if self._summary_response and "kind" in self._summary_response:
            log.debug(self._summary_response["kind"])
            return self._summary_response["kind"]
        log.error(f"An error occurred fetching the cached kind data.")
        return False

    @property
    def sum_ua(self) -> str | bool:
        """
        Retrieves the cached user agent information from the summary data.

        Returns:
            str: User agent information, or False if not available.
        """
        if self._summary_response and "ua" in self._summary_response:
            log.debug(self._summary_response["ua"])
            return self._summary_response["ua"]
        log.error(f"An error occurred fetching the cached user agent data.")
        return False

    @property
    def sum_cpu_info(self) -> dict | bool:
        """
        Retrieves the cached CPU information from the summary data.

        Returns:
            dict: CPU information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"])
            return self._summary_response["cpu"]
        log.error(f"An error occurred fetching the cached CPU data.")
        return False

    @property
    def sum_cpu_brand(self) -> str | bool:
        """
        Retrieves the cached CPU brand information from the summary data.

        Returns:
            str: CPU brand information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["brand"])
            return self._summary_response["cpu"]["brand"]
        log.error(f"An error occurred fetching the cached CPU brand data.")
        return False

    @property
    def sum_cpu_family(self) -> int | bool:
        """
        Retrieves the cached CPU family information from the summary data.

        Returns:
            int: CPU family information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["family"])
            return self._summary_response["cpu"]["family"]
        log.error(f"An error occurred fetching the cached CPU family data.")
        return False

    @property
    def sum_cpu_model(self) -> int | bool:
        """
        Retrieves the cached CPU model information from the summary data.

        Returns:
            int: CPU model information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["model"])
            return self._summary_response["cpu"]["model"]
        log.error(f"An error occurred fetching the cached CPU model data.")
        return False

    @property
    def sum_cpu_stepping(self) -> int | bool:
        """
        Retrieves the cached CPU stepping information from the summary data.

        Returns:
            int: CPU stepping information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["stepping"])
            return self._summary_response["cpu"]["stepping"]
        log.error(f"An error occurred fetching the cached CPU stepping data.")
        return False

    @property
    def sum_cpu_proc_info(self) -> int | bool:
        """
        Retrieves the cached CPU frequency information from the summary data.

        Returns:
            int: CPU frequency information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["proc_info"])
            return self._summary_response["cpu"]["proc_info"]
        log.error(f"An error occurred fetching the cached CPU frequency data.")
        return False

    @property
    def sum_cpu_aes(self) -> int | bool:
        """
        Retrieves the cached CPU aes information from the summary data.

        Returns:
            int: CPU aes information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["aes"])
            return self._summary_response["cpu"]["aes"]
        log.error(f"An error occurred fetching the cached CPU aes data.")
        return False

    @property
    def sum_cpu_avx2(self) -> int | bool:
        """
        Retrieves the cached CPU avx2 information from the summary data.

        Returns:
            int: CPU avx2 information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["avx2"])
            return self._summary_response["cpu"]["avx2"]
        log.error(f"An error occurred fetching the cached CPU avx2 data.")
        return False

    @property
    def sum_cpu_x64(self) -> int | bool:
        """
        Retrieves the cached CPU x64 information from the summary data.

        Returns:
            int: CPU x64 information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["x64"])
            return self._summary_response["cpu"]["x64"]
        log.error(f"An error occurred fetching the cached CPU x64 data.")
        return False

    @property
    def sum_cpu_64_bit(self) -> int | bool:
        """
        Retrieves the cached CPU 64-bit information from the summary data.

        Returns:
            int: CPU 64-bit information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["64_bit"])
            return self._summary_response["cpu"]["64_bit"]
        log.error(f"An error occurred fetching the cached CPU x64-bit data.")
        return False

    @property
    def sum_cpu_l2(self) -> int | bool:
        """
        Retrieves the cached CPU l2 cache information from the summary data.

        Returns:
            int: CPU l2 cache information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["l2"])
            return self._summary_response["cpu"]["l2"]
        log.error(f"An error occurred fetching the cached CPU l2 cache data.")
        return False

    @property
    def sum_cpu_l3(self) -> int | bool:
        """
        Retrieves the cached CPU l3 cache information from the summary data.

        Returns:
            int: CPU l3 cache information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["l3"])
            return self._summary_response["cpu"]["l3"]
        log.error(f"An error occurred fetching the cached CPU l3 cache data.")
        return False

    @property
    def sum_cpu_cores(self) -> int | bool:
        """
        Retrieves the cached CPU cores information from the summary data.

        Returns:
            int: CPU cores information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["cores"])
            return self._summary_response["cpu"]["cores"]
        log.error(f"An error occurred fetching the cached CPU cores data.")
        return False

    @property
    def sum_cpu_threads(self) -> int | bool:
        """
        Retrieves the cached CPU threads information from the summary data.

        Returns:
            int: CPU threads information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["threads"])
            return self._summary_response["cpu"]["threads"]
        log.error(f"An error occurred fetching the cached CPU threads data.")
        return False

    @property
    def sum_cpu_packages(self) -> int | bool:
        """
        Retrieves the cached CPU packages information from the summary data.

        Returns:
            int: CPU packages information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["packages"])
            return self._summary_response["cpu"]["packages"]
        log.error(f"An error occurred fetching the cached CPU packages data.")
        return False

    @property
    def sum_cpu_nodes(self) -> int | bool:
        """
        Retrieves the cached CPU nodes information from the summary data.

        Returns:
            int: CPU nodes information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["nodes"])
            return self._summary_response["cpu"]["nodes"]
        log.error(f"An error occurred fetching the cached CPU nodes data.")
        return False

    @property
    def sum_cpu_backend(self) -> str | bool:
        """
        Retrieves the cached CPU backend information from the summary data.

        Returns:
            str: CPU backend information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["backend"])
            return self._summary_response["cpu"]["backend"]
        log.error(f"An error occurred fetching the cached CPU backend data.")
        return False

    @property
    def sum_cpu_msr(self) -> str | bool:
        """
        Retrieves the cached CPU msr information from the summary data.

        Returns:
            str: CPU msr information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["msr"])
            return self._summary_response["cpu"]["msr"]
        log.error(f"An error occurred fetching the cached CPU msr data.")
        return False

    @property
    def sum_cpu_assembly(self) -> str | bool:
        """
        Retrieves the cached CPU assembly information from the summary data.

        Returns:
            str: CPU assembly information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["assembly"])
            return self._summary_response["cpu"]["assembly"]
        log.error(f"An error occurred fetching the cached CPU assembly data.")
        return False

    @property
    def sum_cpu_arch(self) -> str | bool:
        """
        Retrieves the cached CPU architecture information from the summary data.

        Returns:
            str: CPU architecture information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["arch"])
            return self._summary_response["cpu"]["arch"]
        log.error(f"An error occurred fetching the cached CPU architecture data.")
        return False

    @property
    def sum_cpu_flags(self) -> list | bool:
        """
        Retrieves the cached CPU flags information from the summary data.

        Returns:
            list: CPU flags information, or False if not available.
        """
        if self._summary_response and "cpu" in self._summary_response:
            log.debug(self._summary_response["cpu"]["flags"])
            return self._summary_response["cpu"]["flags"]
        log.error(f"An error occurred fetching the cached CPU flags data.")
        return False

    @property
    def sum_donate_level(self) -> int | bool:
        """
        Retrieves the cached donation level information from the summary data.

        Returns:
            int: Donation level information, or False if not available.
        """
        if self._summary_response and "donate_level" in self._summary_response:
            log.debug(self._summary_response["donate_level"])
            return self._summary_response["donate_level"]
        log.error(f"An error occurred fetching the cached donation level data.")
        return False

    @property
    def sum_paused(self) -> int | bool:
        """
        Retrieves the cached paused status of the miner from the summary data.

        Returns:
            int: True if the miner is paused, False otherwise, or False if not available.
        """
        if self._summary_response and "paused" in self._summary_response:
            log.debug(self._summary_response["paused"])
            return self._summary_response["paused"]
        log.error(f"An error occurred fetching the cached paused status data.")
        return False

    @property
    def sum_algorithms(self) -> list | bool:
        """
        Retrieves the cached algorithms information from the summary data.

        Returns:
            list: Algorithms information, or False if not available.
        """
        if self._summary_response and "algorithms" in self._summary_response:
            log.debug(self._summary_response["algorithms"])
            return self._summary_response["algorithms"]
        log.error(f"An error occurred fetching the cached algorithms data.")
        return False

    @property
    def sum_hashrates(self) -> dict | bool:
        """
        Retrieves the cached current hashrates from the summary data.

        Returns:
            dict: Current hashrates, or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            log.debug(self._summary_response["hashrate"])
            return self._summary_response["hashrate"]
        log.error(f"An error occurred fetching the cached current hashrates data.")
        return False

    @property
    def sum_hashrate_10s(self) -> int | bool:
        """
        Retrieves the cached current hashrate (10s) from the summary data.

        Returns:
            int: Current hashrate (10s), or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            log.debug(self._summary_response["hashrate"]["total"][0])
            return self._summary_response["hashrate"]["total"][0]
        log.error(f"An error occurred fetching the cached current hashrate (10s) data.")
        return False

    @property
    def sum_hashrate_1m(self) -> int | bool:
        """
        Retrieves the cached current hashrate (1m) from the summary data.

        Returns:
            int: Current hashrate (1m), or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            log.debug(self._summary_response["hashrate"]["total"][1])
            return self._summary_response["hashrate"]["total"][1]
        log.error(f"An error occurred fetching the cached current hashrate (1m) data.")
        return False

    @property
    def sum_hashrate_15m(self) -> int | bool:
        """
        Retrieves the cached current hashrate (15m) from the summary data.

        Returns:
            int: Current hashrate (15m), or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            log.debug(self._summary_response["hashrate"]["total"][2])
            return self._summary_response["hashrate"]["total"][2]
        log.error(f"An error occurred fetching the cached current hashrate (15m) data.")
        return False

    @property
    def sum_hashrate_highest(self) -> int | bool:
        """
        Retrieves the cached current hashrate (highest) from the summary data.

        Returns:
            int: Current hashrate (highest), or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            log.debug(self._summary_response["hashrate"]["highest"])
            return self._summary_response["hashrate"]["highest"]
        log.error(f"An error occurred fetching the cached highest hashrate data.")
        return False

    @property
    def sum_hugepages(self) -> list | bool:
        """
        Retrieves the cached current hugepages from the summary data.

        Returns:
            list: Current hugepages, or False if not available.
        """
        if self._summary_response and "hugepages" in self._summary_response:
            log.debug(self._summary_response["hugepages"])
            return self._summary_response["hugepages"]
        log.error(f"An error occurred fetching the cached hugepages data.")
        return False

    # * Data Provided by the backends endpoint
    @property
    def enabled_backends(self) -> list | bool:
        """
        Retrieves the cached currently enabled backends from the backends data.

        Returns:
            list: List of enabled backends, or False if not available.
        """
        backend_types = []
        if self._backends_response:
            for i in self._backends_response:
                if "type" in i and i["enabled"] == True:
                    backend_types.append(i["type"])
            log.debug(backend_types)
            return backend_types
        log.error(f"An error occurred fetching the cached enabled backends data.")
        return False

    @property
    def be_cpu_enabled(self) -> bool | None:
        """
        Retrieves the cached CPU enabled status value from the backends data.

        Returns:
            bool: Bool representing enabled status, or None if not available.
        """
        if self._backends_response and "enabled" in self._backends_response[0]:
            log.debug(self._backends_response[0]["enabled"])
            return self._backends_response[0]["enabled"]
        log.error(f"An error occurred fetching the cached CPU enabled status data.")
        return None

    @property
    def be_cpu_algo(self) -> str | bool:
        """
        Retrieves the cached CPU algorithm information from the backends data.

        Returns:
            str: Bool representing algorithm information, or False if not available.
        """
        if self._backends_response and "algo" in self._backends_response[0]:
            log.debug(self._backends_response[0]["algo"])
            return self._backends_response[0]["algo"]
        log.error(f"An error occurred fetching the cached CPU algorithm data.")
        return False

    @property
    def be_cpu_profile(self) -> str | bool:
        """
        Retrieves the cached CPU profile information from the backends data.

        Returns:
            str: Bool representing profile information, or False if not available.
        """
        if self._backends_response and "profile" in self._backends_response[0]:
            log.debug(self._backends_response[0]["profile"])
            return self._backends_response[0]["profile"]
        log.error(f"An error occurred fetching the cached CPU profile data.")
        return False

    @property
    def be_cpu_hw_aes(self) -> bool | None:
        """
        Retrieves the cached CPU hw-aes support value from the backends data.

        Returns:
            bool: Bool representing hw-aes support status, or None if not available.
        """
        if self._backends_response and "hw-aes" in self._backends_response[0]:
            log.debug(self._backends_response[0]["hw-aes"])
            return self._backends_response[0]["hw-aes"]
        log.error(f"An error occurred fetching the cached CPU hw-aes support data.")
        return None

    @property
    def be_cpu_priority(self) -> int | bool:
        """
        Retrieves the cached CPU priority from the backends data. 

        Value from 1 (lowest priority) to 5 (highest possible priority). Default 
        value `-1` means XMRig doesn't change threads priority at all,

        Returns:
            int: Int representing mining thread priority, or False if not available.
        """
        if self._backends_response and "priority" in self._backends_response[0]:
            log.debug(self._backends_response[0]["priority"])
            return self._backends_response[0]["priority"]
        log.error(f"An error occurred fetching the cached CPU priority data.")
        return False

    @property
    def be_cpu_msr(self) -> bool | None:
        """
        Retrieves the cached CPU msr information from the backends data.

        Returns:
            bool: Bool representing msr information, or None if not available.
        """
        if self._backends_response and "msr" in self._backends_response[0]:
            log.debug(self._backends_response[0]["msr"])
            return self._backends_response[0]["msr"]
        log.error(f"An error occurred fetching the cached CPU msr data.")
        return None

    @property
    def be_cpu_asm(self) -> str | bool:
        """
        Retrieves the cached CPU asm information from the backends data.

        Returns:
            str: Bool representing asm information, or False if not available.
        """
        if self._backends_response and "asm" in self._backends_response[0]:
            log.debug(self._backends_response[0]["asm"])
            return self._backends_response[0]["asm"]
        log.error(f"An error occurred fetching the cached CPU asm data.")
        return False

    @property
    def be_cpu_argon2_impl(self) -> str | bool:
        """
        Retrieves the cached CPU argon2 implementation information from the backends data.

        Returns:
            str: Bool representing argon2 implementation information, or False if not available.
        """
        if self._backends_response and "argon2-impl" in self._backends_response[0]:
            log.debug(self._backends_response[0]["argon2-impl"])
            return self._backends_response[0]["argon2-impl"]
        log.error(f"An error occurred fetching the cached CPU argon2 implementation data.")
        return False

    @property
    def be_cpu_hugepages(self) -> list | bool:
        """
        Retrieves the cached CPU hugepages information from the backends data.

        Returns:
            list: Bool representing hugepages information, or False if not available.
        """
        if self._backends_response and "hugepages" in self._backends_response[0]:
            log.debug(self._backends_response[0]["hugepages"])
            return self._backends_response[0]["hugepages"]
        log.error(f"An error occurred fetching the cached CPU hugepages data.")
        return False

    @property
    def be_cpu_memory(self) -> int | bool:
        """
        Retrieves the cached CPU memory information from the backends data.

        Returns:
            int: Bool representing memory information, or False if not available.
        """
        if self._backends_response and "memory" in self._backends_response[0]:
            log.debug(self._backends_response[0]["memory"])
            return self._backends_response[0]["memory"]
        log.error(f"An error occurred fetching the cached CPU memory data.")
        return False

    @property
    def be_opencl_enabled(self) -> bool | None:
        """
        Retrieves the cached OpenCL enabled information from the backends data.

        Returns:
            bool: Bool representing enabled information, or None if not available.
        """
        if self._backends_response and "enabled" in self._backends_response[1]:
            log.debug(self._backends_response[1]["enabled"])
            return self._backends_response[1]["enabled"]
        log.error(f"An error occurred fetching the cached OpenCL enabled data.")
        return None

    @property
    def be_opencl_algo(self) -> str | bool:
        """
        Retrieves the cached OpenCL algorithm information from the backends data.

        Returns:
            str: Bool representing algorithm information, or False if not available.
        """
        if self._backends_response and "algo" in self._backends_response[1]:
            log.debug(self._backends_response[1]["algo"])
            return self._backends_response[1]["algo"]
        log.error(f"An error occurred fetching the cached OpenCL algorithm data.")
        return False

    @property
    def be_opencl_profile(self) -> str | bool:
        """
        Retrieves the cached OpenCL profile information from the backends data.

        Returns:
            str: Bool representing profile information, or False if not available.
        """
        if self._backends_response and "profile" in self._backends_response[1]:
            log.debug(self._backends_response[1]["profile"])
            return self._backends_response[1]["profile"]
        log.error(f"An error occurred fetching the cached OpenCL profile data.")
        return False

    @property
    def be_opencl_platform(self) -> str | bool:
        """
        Retrieves the cached OpenCL platform information from the backends data.

        Returns:
            str: Bool representing platform information, or False if not available.
        """
        if self._backends_response and "platform" in self._backends_response[1]:
            log.debug(self._backends_response[1]["platform"])
            return self._backends_response[1]["platform"]
        log.error(f"An error occurred fetching the cached OpenCL platform data.")
        return False

    @property
    def be_cuda_type(self) -> str | bool:
        """
        Retrieves the cached Cuda current type info from the backends data.

        Returns:
            str: Current type info, or False if not available.
        """
        if self._backends_response and "type" in self._backends_response[2]:
            log.debug(self._backends_response[2]["type"])
            return self._backends_response[2]["type"]
        log.error(f"An error occurred fetching the cached Cuda type data.")
        return False

    @property
    def be_cuda_enabled(self) -> bool | None:
        """
        Retrieves the cached Cuda current enabled info from the backends data.

        Returns:
            bool: Current enabled info, or None if not available.
        """
        if self._backends_response and "enabled" in self._backends_response[2]:
            log.debug(self._backends_response[2]["enabled"])
            return self._backends_response[2]["enabled"]
        log.error(f"An error occurred fetching the cached Cuda enabled status data.")
        return None

    @property
    def be_cuda_algo(self) -> str | bool:
        """
        Retrieves the cached Cuda algorithm information from the backends data.

        Returns:
            str: Bool representing algorithm information, or False if not available.
        """
        if self._backends_response and "algo" in self._backends_response[2]:
            log.debug(self._backends_response[2]["algo"])
            return self._backends_response[2]["algo"]
        log.error(f"An error occurred fetching the cached Cuda algorithm data.")
        return False

    @property
    def be_cuda_profile(self) -> str | bool:
        """
        Retrieves the cached Cuda profile information from the backends data.

        Returns:
            str: Bool representing profile information, or False if not available.
        """
        if self._backends_response and "profile" in self._backends_response[2]:
            log.debug(self._backends_response[2]["profile"])
            return self._backends_response[2]["profile"]
        log.error(f"An error occurred fetching the cached Cuda profile data.")
        return False

    @property
    def be_cuda_versions(self) -> dict | bool:
        """
        Retrieves the cached Cuda versions information from the backends data.

        Returns:
            dict: Bool representing versions information, or False if not available.
        """
        if self._backends_response and "versions" in self._backends_response[2]:
            log.debug(self._backends_response[2]["versions"])
            return self._backends_response[2]["versions"]
        log.error(f"An error occurred fetching the cached Cuda versions data.")
        return False

    @property
    def be_cuda_runtime(self) -> str | bool:
        """
        Retrieves the cached Cuda runtime information from the backends data.

        Returns:
           str: Bool representing cuda runtime information, or False if not available.
        """
        if self._backends_response and "cuda-runtime" in self._backends_response[2]:
            log.debug(self._backends_response[2]["versions"]["cuda-runtime"])
            return self._backends_response[2]["versions"]["cuda-runtime"]
        log.error(f"An error occurred fetching the cached Cuda runtime data.")
        return False

    @property
    def be_cuda_driver(self) -> str | bool:
        """
        Retrieves the cached Cuda driver information from the backends data.

        Returns:
            str: Bool representing cuda driver information, or False if not available.
        """
        if self._backends_response and "cuda-driver" in self._backends_response[2]:
            log.debug(self._backends_response[2]["versions"]["cuda-driver"])
            return self._backends_response[2]["versions"]["cuda-driver"]
        log.error(f"An error occurred fetching the cached Cuda driver data.")
        return False

    @property
    def be_cuda_plugin(self) -> str | bool:
        """
        Retrieves the cached Cuda plugin information from the backends data.

        Returns:
            str: Bool representing cuda plugin information, or False if not available.
        """
        if self._backends_response and "plugin" in self._backends_response[2]:
            log.debug(self._backends_response[2]["versions"]["plugin"])
            return self._backends_response[2]["versions"]["plugin"]
        log.error(f"An error occurred fetching the cached Cuda plugin data.")
        return False

    @property
    def be_cuda_hashrate(self) -> list | bool:
        """
        Retrieves the cached Cuda current hashrate info from the backends data.

        Returns:
            list: Current hashrate info, or False if not available.
        """
        if self._backends_response and "hashrate" in self._backends_response[2]:
            log.debug(self._backends_response[2]["hashrate"])
            return self._backends_response[2]["hashrate"]
        log.error(f"An error occurred fetching the cached Cuda current hashrate data.")
        return False

    @property
    def be_cuda_hashrate_10s(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (10s) info from the backends data.

        Returns:
           int: Current hashrate (10s) info, or False if not available.
        """
        if self._backends_response and "hashrate" in self._backends_response[2]:
            log.debug(self._backends_response[2]["hashrate"][0])
            return self._backends_response[2]["hashrate"][0]
        log.error(f"An error occurred fetching the cached Cuda current hashrate (10s) data.")
        return False

    @property
    def be_cuda_hashrate_1m(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (1m) info from the backends data.

        Returns:
            int: Current hashrate (1m) info, or False if not available.
        """
        if self._backends_response and "hashrate" in self._backends_response[2]:
            log.debug(self._backends_response[2]["hashrate"][1])
            return self._backends_response[2]["hashrate"][1]
        log.error(f"An error occurred fetching the cached Cuda current hashrate (1m) data.")
        return False

    @property
    def be_cuda_hashrate_15m(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (15m) info from the backends data.

        Returns:
            int: Current hashrate (15m) info, or False if not available.
        """
        if self._backends_response and "hashrate" in self._backends_response[2]:
            log.debug(self._backends_response[2]["hashrate"][2])
            return self._backends_response[2]["hashrate"][2]
        log.error(f"An error occurred fetching the cached Cuda current hashrate (15m) data.")
        return False

    @property
    def be_cuda_threads(self) -> dict | bool:
        """
        Retrieves the cached Cuda current threads info from the backends data.

        Returns:
            dict: Current threads info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            log.debug(self._backends_response[2]["threads"][0])
            return self._backends_response[2]["threads"][0]
        log.error(f"An error occurred fetching the cached Cuda threads data.")
        return False

    @property
    def be_cuda_threads_index(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads index info from the backends data.

        Returns:
            int: Current threads index info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            log.debug(self._backends_response[2]["threads"][0]["index"])
            return self._backends_response[2]["threads"][0]["index"]
        log.error(f"An error occurred fetching the cached Cuda threads index data.")
        return False

    @property
    def be_cuda_threads_amount(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads amount info from the backends data.

        Returns:
            int: Current threads amount info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            log.debug(self._backends_response[2]["threads"][0]["threads"])
            return self._backends_response[2]["threads"][0]["threads"]
        log.error(f"An error occurred fetching the cached Cuda threads amount data.")
        return False

    @property
    def be_cuda_threads_blocks(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads blocks info from the backends data.

        Returns:
            int: Current threads blocks info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            log.debug(self._backends_response[2]["threads"][0]["blocks"])
            return self._backends_response[2]["threads"][0]["blocks"]
        log.error(f"An error occurred fetching the cached Cuda threads blocks data.")
        return False

    @property
    def be_cuda_threads_bfactor(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads bfactor info from the backends data.

        Returns:
            int: Current threads bfactor info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            log.debug(self._backends_response[2]["threads"][0]["bfactor"])
            return self._backends_response[2]["threads"][0]["bfactor"]
        log.error(f"An error occurred fetching the cached Cuda threads bfactor data.")
        return False

    @property
    def be_cuda_threads_bsleep(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads bsleep info from the backends data.

        Returns:
            int: Current threads bsleep info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            log.debug(self._backends_response[2]["threads"][0]["bsleep"])
            return self._backends_response[2]["threads"][0]["bsleep"]
        log.error(f"An error occurred fetching the cached Cuda threads bsleep data.")
        return False

    @property
    def be_cuda_threads_affinity(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads affinity info from the backends data.

        Returns:
            int: Current threads affinity info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            log.debug(self._backends_response[2]["threads"][0]["affinity"])
            return self._backends_response[2]["threads"][0]["affinity"]
        log.error(f"An error occurred fetching the cached Cuda threads affinity data.")
        return False

    @property
    def be_cuda_threads_dataset_host(self) -> bool | None:
        """
        Retrieves the cached Cuda current threads dataset host info from the backends data.

        Returns:
            bool: Current threads dataset host info, or None if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            log.debug(self._backends_response[2]["threads"][0]["dataset_host"])
            return self._backends_response[2]["threads"][0]["dataset_host"]
        log.error(f"An error occurred fetching the cached Cuda threads dataset host data.")
        return None

    @property
    def be_cuda_threads_hashrates(self) -> list | bool:
        """
        Retrieves the cached Cuda current hashrates (10s/1m/15m) from the summary data.

        Returns:
            list: Current hashrates, or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            log.debug(self._backends_response[2]["threads"][0]["hashrate"])
            return self._backends_response[2]["threads"][0]["hashrate"]
        log.error(f"An error occurred fetching the cached Cuda threads hashrates data.")
        return False

    @property
    def be_cuda_threads_hashrate_10s(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (10s) from the summary data.

        Returns:
            int: Current hashrate (10s), or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            log.debug(self._backends_response[2]["threads"][0]["hashrate"][0])
            return self._backends_response[2]["threads"][0]["hashrate"][0]
        log.error(f"An error occurred fetching the cached Cuda threads hashrate (10s) data.")
        return False

    @property
    def be_cuda_threads_hashrate_1m(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (1m) from the summary data.

        Returns:
            int: Current hashrate (1m), or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            log.debug(self._backends_response[2]["threads"][0]["hashrate"][1])
            return self._backends_response[2]["threads"][0]["hashrate"][1]
        log.error(f"An error occurred fetching the cached Cuda threads hashrates (1m) data.")
        return False

    @property
    def be_cuda_threads_hashrate_15m(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (15m) from the summary data.

        Returns:
            int: Current hashrate (15m), or False if not available.
        """
        if self._summary_response and "hashrate" in self._summary_response:
            log.debug(self._backends_response[2]["threads"][0]["hashrate"][2])
            return self._backends_response[2]["threads"][0]["hashrate"][2]
        log.error(f"An error occurred fetching the cached Cuda threads hashrates (15m) data.")
        return False

    @property
    def be_cuda_threads_name(self) -> str | bool:
        """
        Retrieves the cached Cuda current threads name info from the backends data.

        Returns:
            str: Current threads name info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            log.debug(self._backends_response[2]["threads"][0]["name"])
            return self._backends_response[2]["threads"][0]["name"]
        log.error(f"An error occurred fetching the cached Cuda threads name data.")
        return False

    @property
    def be_cuda_threads_bus_id(self) -> str | bool:
        """
        Retrieves the cached Cuda current threads bus ID info from the backends data.

        Returns:
            str: Current threads bus ID info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            log.debug(self._backends_response[2]["threads"][0]["bus_id"])
            return self._backends_response[2]["threads"][0]["bus_id"]
        log.error(f"An error occurred fetching the cached Cuda threads bus ID data.")
        return False

    @property
    def be_cuda_threads_smx(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads smx info from the backends data.

        Returns:
            int: Current threads smx info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            log.debug(self._backends_response[2]["threads"][0]["smx"])
            return self._backends_response[2]["threads"][0]["smx"]
        log.error(f"An error occurred fetching the cached Cuda threads smx data.")
        return False

    @property
    def be_cuda_threads_arch(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads arch info from the backends data.

        Returns:
            int: Current threads arch info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            log.debug(self._backends_response[2]["threads"][0]["arch"])
            return self._backends_response[2]["threads"][0]["arch"]
        log.error(f"An error occurred fetching the cached Cuda threads arch data.")
        return False

    @property
    def be_cuda_threads_global_mem(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads global memory info from the backends data.

        Returns:
            int: Current threads global mem info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            log.debug(self._backends_response[2]["threads"][0]["global_mem"])
            return self._backends_response[2]["threads"][0]["global_mem"]
        log.error(f"An error occurred fetching the cached Cuda threads global memory data.")
        return False

    @property
    def be_cuda_threads_clock(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads clock info from the backends data.

        Returns:
            int: Current threads clock info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            log.debug(self._backends_response[2]["threads"][0]["clock"])
            return self._backends_response[2]["threads"][0]["clock"]
        log.error(f"An error occurred fetching the cached Cuda threads clock info data.")
        return False

    @property
    def be_cuda_threads_memory_clock(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads memory clock info from the backends data.

        Returns:
            int: Current threads memory_clock info, or False if not available.
        """
        if self._backends_response and "threads" in self._backends_response[2]:
            log.debug(self._backends_response[2]["threads"][0]["memory_clock"])
            return self._backends_response[2]["threads"][0]["memory_clock"]
        log.error(f"An error occurred fetching the cached Cuda threads memory clock data.")
        return False

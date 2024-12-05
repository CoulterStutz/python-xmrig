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
        log.info(f"XMRigAPI initialized for {self._base_url}")

    def _set_auth_header(self) -> bool:
        """
        Update the Authorization header for the HTTP requests.

        Returns:
            bool: True if the Authorization header was changed, or False if an error occurred.
        """
        try:
            self._headers['Authorization'] = f"Bearer {self._access_token}"
            log.debug(f"Authorization header successfully changed.")
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
            log.debug(f"Summary endpoint successfully fetched.")
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
            log.debug(f"Backends endpoint successfully fetched.")
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
            log.debug(f"Config endpoint successfully fetched.")
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
            log.debug(f"Config endpoint successfully updated.")
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
            log.debug(f"All endpoints successfully fetched.")
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
            log.debug(f"Miner successfully paused.")
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
            log.debug(f"Miner successfully resumed.")
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
            log.debug(f"Miner successfully stopped.")
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
            log.debug(f"Miner successfully started.")
            return True
        except requests.exceptions.RequestException as e:
            log.error(f"An error occurred starting the miner: {e}")
            return False

    @property
    def summary(self) -> dict | bool:
        """
        Retrieves the entire cached summary endpoint data.

        Returns:
            dict: Current summary response, or False if not available.
        """
        try:
            log.debug(self._summary_response)
            return self._summary_response
        except Exception as e:
            log.error(f"An error occurred fetching the cached summary data: {e}")
            return False

    @property
    def backends(self) -> dict | bool:
        """
        Retrieves the entire cached backends endpoint data.

        Returns:
            dict: Current backends response, or False if not available.
        """
        try:
            log.debug(self._backends_response)
            return self._backends_response
        except Exception as e:
            log.error(f"An error occurred fetching the cached backends data: {e}")
            return False

    @property
    def config(self) -> dict | bool:
        """
        Retrieves the entire cached config endpoint data.

        Returns:
            dict: Current config response, or False if not available.
        """
        try:
            log.debug(self._config_response)
            return self._config_response
        except Exception as e:
            log.error(f"An error occurred fetching the cached config data: {e}")
            return False

    # ***** data provided by summary endpoint

    @property
    def sum_id(self) -> str | bool:
        """
        Retrieves the cached ID information from the summary data.

        Returns:
            str: ID information, or False if not available.
        """
        try:
            log.debug(self._summary_response["id"])
            return self._summary_response["id"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached ID information data: {e}")
            return False

    @property
    def sum_worker_id(self) -> str | bool:
        """
        Retrieves the cached worker ID information from the summary data.

        Returns:
            str: Worker ID information, or False if not available.
        """
        try:
            log.debug(self._summary_response["worker_id"])
            return self._summary_response["worker_id"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached worker ID information data: {e}")
            return False

    @property
    def sum_uptime(self) -> int | bool:
        """
        Retrieves the cached current uptime from the summary data.

        Returns:
            int: Current uptime in seconds, or False if not available.
        """
        try:
            log.debug(self._summary_response["uptime"])
            return self._summary_response["uptime"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached current uptime data: {e}")
            return False

    @property
    def sum_uptime_readable(self) -> str | bool:
        """
        Retrieves the cached uptime in a human-readable format from the summary data.

        Returns:
            str: Uptime in the format "days, hours:minutes:seconds", or False if not available.
        """
        try:
            log.debug(str(timedelta(seconds=self._summary_response["uptime"])))
            return str(timedelta(seconds=self._summary_response["uptime"]))
        except Exception as e:
            log.error(f"An error occurred fetching the cached current uptime in a human-readable format data: {e}")
            return False

    @property
    def sum_restricted(self) -> bool | None:
        """
        Retrieves the cached current restricted status from the summary data.

        Returns:
            bool: Current restricted status, or None if not available.
        """
        try:
            log.debug(self._summary_response["restricted"])
            return self._summary_response["restricted"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached restricted status data: {e}")
            return None

    @property
    def sum_resources(self) -> dict | bool:
        """
        Retrieves the cached resources information from the summary data.

        Returns:
            dict: Resources information, or False if not available.
        """
        try:
            log.debug(self._summary_response["resources"])
            return self._summary_response["resources"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached resources data: {e}")
            return False

    @property
    def sum_memory_usage(self) -> dict | bool:
        """
        Retrieves the cached memory usage from the summary data.

        Returns:
            dict: Memory usage information, or False if not available.
        """
        try:
            log.debug(self._summary_response["resources"]["memory"])
            return self._summary_response["resources"]["memory"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached memory usage data: {e}")
            return False

    @property
    def sum_free_memory(self) -> int | bool:
        """
        Retrieves the cached free memory from the summary data.

        Returns:
            int: Free memory information, or False if not available.
        """
        try:
            log.debug(self._summary_response["resources"]["memory"]["free"])
            return self._summary_response["resources"]["memory"]["free"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached free memory data: {e}")
            return False

    @property
    def sum_total_memory(self) -> int | bool:
        """
        Retrieves the cached total memory from the summary data.

        Returns:
            int: Total memory information, or False if not available.
        """
        try:
            log.debug(self._summary_response["resources"]["memory"]["total"])
            return self._summary_response["resources"]["memory"]["total"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached total memory data: {e}")
            return False

    @property
    def sum_resident_set_memory(self) -> int | bool:
        """
        Retrieves the cached resident set memory from the summary data.

        Returns:
            int: Resident set memory information, or False if not available.
        """
        try:
            log.debug(self._summary_response["resources"]["memory"]["resident_set_memory"])
            return self._summary_response["resources"]["memory"]["resident_set_memory"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached resident set memory data: {e}")
            return False

    @property
    def sum_load_average(self) -> list | bool:
        """
        Retrieves the cached load average from the summary data.

        Returns:
            list: Load average information, or False if not available.
        """
        try:
            log.debug(self._summary_response["resources"]["load_average"])
            return self._summary_response["resources"]["load_average"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached load average data: {e}")
            return False

    @property
    def sum_hardware_concurrency(self) -> int | bool:
        """
        Retrieves the cached hardware concurrency from the summary data.

        Returns:
            int: Hardware concurrency information, or False if not available.
        """
        try:
            log.debug(self._summary_response["resources"]["hardware_concurrency"])
            return self._summary_response["resources"]["hardware_concurrency"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached hardware concurrency data: {e}")
            return False

    @property
    def sum_features(self) -> list | bool:
        """
        Retrieves the cached supported features information from the summary data.

        Returns:
            list: Supported features information, or False if not available.
        """
        try:
            log.debug(self._summary_response["resources"]["features"])
            return self._summary_response["resources"]["features"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached features data: {e}")
            return False

    @property
    def sum_results(self) -> dict | bool:
        """
        Retrieves the cached results information from the summary data.

        Returns:
            dict: Results information, or False if not available.
        """
        try:
            log.debug(self._summary_response["results"])
            return self._summary_response["results"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached results data: {e}")
            return False

    @property
    def sum_current_difficulty(self) -> int | bool:
        """
        Retrieves the cached current difficulty from the summary data.

        Returns:
            int: Current difficulty, or False if not available.
        """
        try:
            log.debug(self._summary_response["results"]["diff_current"])
            return self._summary_response["results"]["diff_current"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached current difficulty data: {e}")
            return False

    @property
    def sum_good_shares(self) -> int | bool:
        """
        Retrieves the cached good shares from the summary data.

        Returns:
            int: Good shares, or False if not available.
        """
        try:
            log.debug(self._summary_response["results"]["shares_good"])
            return self._summary_response["results"]["shares_good"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached good shares data: {e}")
            return False

    @property
    def sum_total_shares(self) -> int | bool:
        """
        Retrieves the cached total shares from the summary data.

        Returns:
            int: Total shares, or False if not available.
        """
        try:
            log.debug(self._summary_response["results"]["shares_total"])
            return self._summary_response["results"]["shares_total"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached total shares data: {e}")
            return False

    @property
    def sum_avg_time(self) -> int | bool:
        """
        Retrieves the cached average time information from the summary data.

        Returns:
            int: Average time information, or False if not available.
        """
        try:
            log.debug(self._summary_response["results"]["avg_time"])
            return self._summary_response["results"]["avg_time"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached average time data: {e}")
            return False

    @property
    def sum_avg_time_ms(self) -> int | bool:
        """
        Retrieves the cached average time in `ms` information from the summary data.

        Returns:
            int: Average time in `ms` information, or False if not available.
        """
        try:
            log.debug(self._summary_response["results"]["avg_time_ms"])
            return self._summary_response["results"]["avg_time_ms"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached average time in `ms` data: {e}")
            return False

    @property
    def sum_total_hashes(self) -> int | bool:
        """
        Retrieves the cached total number of hashes from the summary data.

        Returns:
            int: Total number of hashes, or False if not available.
        """
        try:
            log.debug(self._summary_response["results"]["hashes_total"])
            return self._summary_response["results"]["hashes_total"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached total hashes data: {e}")
            return False

    @property
    def sum_best_results(self) -> list | bool:
        """
        Retrieves the cached best results from the summary data.

        Returns:
            list: Best results, or False if not available.
        """
        try:
            log.debug(self._summary_response["results"]["best"])
            return self._summary_response["results"]["best"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached best results data: {e}")
            return False

    @property
    def sum_algorithm(self) -> str | bool:
        """
        Retrieves the cached current mining algorithm from the summary data.

        Returns:
            str: Current mining algorithm, or False if not available.
        """
        try:
            log.debug(self._summary_response["algo"])
            return self._summary_response["algo"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached current mining alogorithm data: {e}")
            return False

    @property
    def sum_connection(self) -> dict | bool:
        """
        Retrieves the cached connection information from the summary data.

        Returns:
            dict: Connection information, or False if not available.
        """
        try:
            log.debug(self._summary_response["connection"])
            return self._summary_response["connection"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached connection data: {e}")
            return False

    @property
    def sum_pool_info(self) -> str | bool:
        """
        Retrieves the cached pool information from the summary data.

        Returns:
            str: Pool information, or False if not available.
        """
        try:
            log.debug(self._summary_response["connection"]["pool"])
            return self._summary_response["connection"]["pool"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached pool information data: {e}")
            return False

    @property
    def sum_pool_ip_address(self) -> str | bool:
        """
        Retrieves the cached IP address from the summary data.

        Returns:
            str: IP address, or False if not available.
        """
        try:
            log.debug(self._summary_response["connection"]["ip"])
            return self._summary_response["connection"]["ip"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached IP address data: {e}")
            return False

    @property
    def sum_pool_uptime(self) -> int | bool:
        """
        Retrieves the cached pool uptime information from the summary data.

        Returns:
            int: Pool uptime information, or False if not available.
        """
        try:
            log.debug(self._summary_response["connection"]["uptime"])
            return self._summary_response["connection"]["uptime"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached pool uptime data: {e}")
            return False

    @property
    def sum_pool_uptime_ms(self) -> int | bool:
        """
        Retrieves the cached pool uptime in ms from the summary data.

        Returns:
            int: Pool uptime in ms, or False if not available.
        """
        try:
            log.debug(self._summary_response["connection"]["uptime_ms"])
            return self._summary_response["connection"]["uptime_ms"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached pool uptime in `ms` data: {e}")
            return False

    @property
    def sum_pool_ping(self) -> int | bool:
        """
        Retrieves the cached pool ping information from the summary data.

        Returns:
            int: Pool ping information, or False if not available.
        """
        try:
            log.debug(self._summary_response["connection"]["ping"])
            return self._summary_response["connection"]["ping"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached pool ping data: {e}")
            return False

    @property
    def sum_pool_failures(self) -> int | bool:
        """
        Retrieves the cached pool failures information from the summary data.

        Returns:
            int: Pool failures information, or False if not available.
        """
        try:
            log.debug(self._summary_response["connection"]["failures"])
            return self._summary_response["connection"]["failures"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached pool failures data: {e}")
            return False

    @property
    def sum_pool_tls(self) -> bool | None:
        """
        Retrieves the cached pool tls status from the summary data.

        Returns:
            bool: Pool tls status, or None if not available.
        """
        try:
            log.debug(self._summary_response["connection"]["tls"])
            return self._summary_response["connection"]["tls"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached pool tls data: {e}")
            return None

    @property
    def sum_pool_tls_fingerprint(self) -> str | bool:
        """
        Retrieves the cached pool tls fingerprint information from the summary data.

        Returns:
            str: Pool tls fingerprint information, or False if not available.
        """
        try:
            log.debug(self._summary_response["connection"]["tls-fingerprint"])
            return self._summary_response["connection"]["tls-fingerprint"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached pool tls fingerprint data: {e}")
            return False

    @property
    def sum_pool_algo(self) -> str | bool:
        """
        Retrieves the cached pool algorithm information from the summary data.

        Returns:
            str: Pool algorithm information, or False if not available.
        """
        try:
            log.debug(self._summary_response["connection"]["algo"])
            return self._summary_response["connection"]["algo"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached pool algorithm data: {e}")
            return False

    @property
    def sum_pool_diff(self) -> int | bool:
        """
        Retrieves the cached pool difficulty information from the summary data.

        Returns:
            int: Pool difficulty information, or False if not available.
        """
        try:
            log.debug(self._summary_response["connection"]["diff"])
            return self._summary_response["connection"]["diff"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached pool difficulty data: {e}")
            return False

    @property
    def sum_pool_accepted_jobs(self) -> int | bool:
        """
        Retrieves the cached number of accepted jobs from the summary data.

        Returns:
            int: Number of accepted jobs, or False if not available.
        """
        try:
            log.debug(self._summary_response["connection"]["accepted"])
            return self._summary_response["connection"]["accepted"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached pool accepted jobs data: {e}")
            return False

    @property
    def sum_pool_rejected_jobs(self) -> int | bool:
        """
        Retrieves the cached number of rejected jobs from the summary data.

        Returns:
            int: Number of rejected jobs, or False if not available.
        """
        try:
            log.debug(self._summary_response["connection"]["rejected"])
            return self._summary_response["connection"]["rejected"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached pool rejected jobs data: {e}")
            return False

    @property
    def sum_pool_average_time(self) -> int | bool:
        """
        Retrieves the cached pool average time information from the summary data.

        Returns:
            int: Pool average time information, or False if not available.
        """
        try:
            log.debug(self._summary_response["connection"]["avg_time"])
            return self._summary_response["connection"]["avg_time"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached pool average time data: {e}")
            return False

    @property
    def sum_pool_average_time_ms(self) -> int | bool:
        """
        Retrieves the cached pool average time in ms from the summary data.

        Returns:
            int: Pool average time in ms, or False if not available.
        """
        try:
            log.debug(self._summary_response["connection"]["avg_time_ms"])
            return self._summary_response["connection"]["avg_time_ms"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached pool average time in `ms` data: {e}")
            return False

    @property
    def sum_pool_total_hashes(self) -> int | bool:
        """
        Retrieves the cached pool total hashes information from the summary data.

        Returns:
            int: Pool total hashes information, or False if not available.
        """
        try:
            log.debug(self._summary_response["connection"]["hashes_total"])
            return self._summary_response["connection"]["hashes_total"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached pool total hashes data: {e}")
            return False

    @property
    def sum_version(self) -> str | bool:
        """
        Retrieves the cached version information from the summary data.

        Returns:
            str: Version information, or False if not available.
        """
        try:
            log.debug(self._summary_response["version"])
            return self._summary_response["version"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached version data: {e}")
            return False

    @property
    def sum_kind(self) -> str | bool:
        """
        Retrieves the cached kind information from the summary data.

        Returns:
            str: Kind information, or False if not available.
        """
        try:
            log.debug(self._summary_response["kind"])
            return self._summary_response["kind"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached kind data: {e}")
            return False

    @property
    def sum_ua(self) -> str | bool:
        """
        Retrieves the cached user agent information from the summary data.

        Returns:
            str: User agent information, or False if not available.
        """
        try:
            log.debug(self._summary_response["ua"])
            return self._summary_response["ua"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached user agent data: {e}")
            return False

    @property
    def sum_cpu_info(self) -> dict | bool:
        """
        Retrieves the cached CPU information from the summary data.

        Returns:
            dict: CPU information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"])
            return self._summary_response["cpu"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU data: {e}")
            return False

    @property
    def sum_cpu_brand(self) -> str | bool:
        """
        Retrieves the cached CPU brand information from the summary data.

        Returns:
            str: CPU brand information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["brand"])
            return self._summary_response["cpu"]["brand"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU brand data: {e}")
            return False

    @property
    def sum_cpu_family(self) -> int | bool:
        """
        Retrieves the cached CPU family information from the summary data.

        Returns:
            int: CPU family information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["family"])
            return self._summary_response["cpu"]["family"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU family data: {e}")
            return False

    @property
    def sum_cpu_model(self) -> int | bool:
        """
        Retrieves the cached CPU model information from the summary data.

        Returns:
            int: CPU model information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["model"])
            return self._summary_response["cpu"]["model"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU model data: {e}")
            return False

    @property
    def sum_cpu_stepping(self) -> int | bool:
        """
        Retrieves the cached CPU stepping information from the summary data.

        Returns:
            int: CPU stepping information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["stepping"])
            return self._summary_response["cpu"]["stepping"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU stepping data: {e}")
            return False

    @property
    def sum_cpu_proc_info(self) -> int | bool:
        """
        Retrieves the cached CPU frequency information from the summary data.

        Returns:
            int: CPU frequency information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["proc_info"])
            return self._summary_response["cpu"]["proc_info"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU frequency data: {e}")
            return False

    @property
    def sum_cpu_aes(self) -> bool | None:
        """
        Retrieves the cached CPU aes information from the summary data.

        Returns:
            bool: CPU aes information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["aes"])
            return self._summary_response["cpu"]["aes"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU aes data: {e}")
            return None

    @property
    def sum_cpu_avx2(self) -> bool | None:
        """
        Retrieves the cached CPU avx2 information from the summary data.

        Returns:
            bool: CPU avx2 information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["avx2"])
            return self._summary_response["cpu"]["avx2"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU avx2 data: {e}")
            return None

    @property
    def sum_cpu_x64(self) -> bool | None:
        """
        Retrieves the cached CPU x64 information from the summary data.

        Returns:
            bool: CPU x64 information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["x64"])
            return self._summary_response["cpu"]["x64"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU x64 data: {e}")
            return None

    @property
    def sum_cpu_64_bit(self) -> bool | None:
        """
        Retrieves the cached CPU 64-bit information from the summary data.

        Returns:
            bool: CPU 64-bit information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["64_bit"])
            return self._summary_response["cpu"]["64_bit"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU x64-bit data: {e}")
            return None

    @property
    def sum_cpu_l2(self) -> int | bool:
        """
        Retrieves the cached CPU l2 cache information from the summary data.

        Returns:
            int: CPU l2 cache information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["l2"])
            return self._summary_response["cpu"]["l2"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU l2 cache data: {e}")
            return False

    @property
    def sum_cpu_l3(self) -> int | bool:
        """
        Retrieves the cached CPU l3 cache information from the summary data.

        Returns:
            int: CPU l3 cache information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["l3"])
            return self._summary_response["cpu"]["l3"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU l3 cache data: {e}")
            return False

    @property
    def sum_cpu_cores(self) -> int | bool:
        """
        Retrieves the cached CPU cores information from the summary data.

        Returns:
            int: CPU cores information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["cores"])
            return self._summary_response["cpu"]["cores"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU cores data: {e}")
            return False

    @property
    def sum_cpu_threads(self) -> int | bool:
        """
        Retrieves the cached CPU threads information from the summary data.

        Returns:
            int: CPU threads information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["threads"])
            return self._summary_response["cpu"]["threads"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU threads data: {e}")
            return False

    @property
    def sum_cpu_packages(self) -> int | bool:
        """
        Retrieves the cached CPU packages information from the summary data.

        Returns:
            int: CPU packages information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["packages"])
            return self._summary_response["cpu"]["packages"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU packages data: {e}")
            return False

    @property
    def sum_cpu_nodes(self) -> int | bool:
        """
        Retrieves the cached CPU nodes information from the summary data.

        Returns:
            int: CPU nodes information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["nodes"])
            return self._summary_response["cpu"]["nodes"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU nodes data: {e}")
            return False

    @property
    def sum_cpu_backend(self) -> str | bool:
        """
        Retrieves the cached CPU backend information from the summary data.

        Returns:
            str: CPU backend information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["backend"])
            return self._summary_response["cpu"]["backend"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU backend data: {e}")
            return False

    @property
    def sum_cpu_msr(self) -> str | bool:
        """
        Retrieves the cached CPU msr information from the summary data.

        Returns:
            str: CPU msr information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["msr"])
            return self._summary_response["cpu"]["msr"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU msr data: {e}")
            return False

    @property
    def sum_cpu_assembly(self) -> str | bool:
        """
        Retrieves the cached CPU assembly information from the summary data.

        Returns:
            str: CPU assembly information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["assembly"])
            return self._summary_response["cpu"]["assembly"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU assembly data: {e}")
            return False

    @property
    def sum_cpu_arch(self) -> str | bool:
        """
        Retrieves the cached CPU architecture information from the summary data.

        Returns:
            str: CPU architecture information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["arch"])
            return self._summary_response["cpu"]["arch"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU architecture data: {e}")
            return False

    @property
    def sum_cpu_flags(self) -> list | bool:
        """
        Retrieves the cached CPU flags information from the summary data.

        Returns:
            list: CPU flags information, or False if not available.
        """
        try:
            log.debug(self._summary_response["cpu"]["flags"])
            return self._summary_response["cpu"]["flags"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU flags data: {e}")
            return False

    @property
    def sum_donate_level(self) -> int | bool:
        """
        Retrieves the cached donation level information from the summary data.

        Returns:
            int: Donation level information, or False if not available.
        """
        try:
            log.debug(self._summary_response["donate_level"])
            return self._summary_response["donate_level"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached donation level data: {e}")
            return False

    @property
    def sum_paused(self) -> bool | None:
        """
        Retrieves the cached paused status of the miner from the summary data.

        Returns:
            bool: True if the miner is paused, False otherwise, or None if not available.
        """
        try:
            log.debug(self._summary_response["paused"])
            return self._summary_response["paused"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached paused status data: {e}")
            return None

    @property
    def sum_algorithms(self) -> list | bool:
        """
        Retrieves the cached algorithms information from the summary data.

        Returns:
            list: Algorithms information, or False if not available.
        """
        try:
            log.debug(self._summary_response["algorithms"])
            return self._summary_response["algorithms"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached algorithms data: {e}")
            return False

    @property
    def sum_hashrates(self) -> dict | bool:
        """
        Retrieves the cached current hashrates from the summary data.

        Returns:
            dict: Current hashrates, or False if not available.
        """
        try:
            log.debug(self._summary_response["hashrate"])
            return self._summary_response["hashrate"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached current hashrates data: {e}")
            return False

    @property
    def sum_hashrate_10s(self) -> int | bool:
        """
        Retrieves the cached current hashrate (10s) from the summary data.

        Returns:
            int: Current hashrate (10s), or False if not available.
        """
        try:
            log.debug(self._summary_response["hashrate"]["total"][0])
            return self._summary_response["hashrate"]["total"][0]
        except Exception as e:
            log.error(f"An error occurred fetching the cached current hashrate (10s) data: {e}")
            return False

    @property
    def sum_hashrate_1m(self) -> int | bool:
        """
        Retrieves the cached current hashrate (1m) from the summary data.

        Returns:
            int: Current hashrate (1m), or False if not available.
        """
        try:
            log.debug(self._summary_response["hashrate"]["total"][1])
            return self._summary_response["hashrate"]["total"][1]
        except Exception as e:
            log.error(f"An error occurred fetching the cached current hashrate (1m) data: {e}")
            return False

    @property
    def sum_hashrate_15m(self) -> int | bool:
        """
        Retrieves the cached current hashrate (15m) from the summary data.

        Returns:
            int: Current hashrate (15m), or False if not available.
        """
        try:
            log.debug(self._summary_response["hashrate"]["total"][2])
            return self._summary_response["hashrate"]["total"][2]
        except Exception as e:
            log.error(f"An error occurred fetching the cached current hashrate (15m) data: {e}")
            return False

    @property
    def sum_hashrate_highest(self) -> int | bool:
        """
        Retrieves the cached current hashrate (highest) from the summary data.

        Returns:
            int: Current hashrate (highest), or False if not available.
        """
        try:
            log.debug(self._summary_response["hashrate"]["highest"])
            return self._summary_response["hashrate"]["highest"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached highest hashrate data: {e}")
            return False

    @property
    def sum_hugepages(self) -> list | bool:
        """
        Retrieves the cached current hugepages from the summary data.

        Returns:
            list: Current hugepages, or False if not available.
        """
        try:
            log.debug(self._summary_response["hugepages"])
            return self._summary_response["hugepages"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached hugepages data: {e}")
            return False

    # ***** Data Provided by the backends endpoint

    @property
    def enabled_backends(self) -> list | bool:
        """
        Retrieves the cached currently enabled backends from the backends data.

        Returns:
            list: List of enabled backends, or False if not available.
        """
        backend_types = []
        try:
            for i in self._backends_response:
                if "type" in i and i["enabled"] == True:
                    backend_types.append(i["type"])
            log.debug(backend_types)
            return backend_types
        except Exception as e:
            log.error(f"An error occurred fetching the cached enabled backends data: {e}")
            return False
    
    @property
    def be_cpu_type(self) -> str | bool:
        """
        Retrieves the cached CPU type status value from the backends data.

        Returns:
            str: Type, or None if not available.
        """
        try:
            log.debug(self._backends_response[0]["type"])
            return self._backends_response[0]["type"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU type status data: {e}")
            return False

    @property
    def be_cpu_enabled(self) -> bool | None:
        """
        Retrieves the cached CPU enabled status value from the backends data.

        Returns:
            bool: Bool representing enabled status, or None if not available.
        """
        try:
            log.debug(self._backends_response[0]["enabled"])
            return self._backends_response[0]["enabled"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU enabled status data: {e}")
            return None

    @property
    def be_cpu_algo(self) -> str | bool:
        """
        Retrieves the cached CPU algorithm information from the backends data.

        Returns:
            str: Algorithm information, or False if not available.
        """
        try:
            log.debug(self._backends_response[0]["algo"])
            return self._backends_response[0]["algo"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU algorithm data: {e}")
            return False

    @property
    def be_cpu_profile(self) -> str | bool:
        """
        Retrieves the cached CPU profile information from the backends data.

        Returns:
            str: Profile information, or False if not available.
        """
        try:
            log.debug(self._backends_response[0]["profile"])
            return self._backends_response[0]["profile"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU profile data: {e}")
            return False

    @property
    def be_cpu_hw_aes(self) -> bool | None:
        """
        Retrieves the cached CPU hw-aes support value from the backends data.

        Returns:
            bool: Bool representing hw-aes support status, or None if not available.
        """
        try:
            log.debug(self._backends_response[0]["hw-aes"])
            return self._backends_response[0]["hw-aes"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU hw-aes support data: {e}")
            return None

    @property
    def be_cpu_priority(self) -> int | bool:
        """
        Retrieves the cached CPU priority from the backends data. 

        Value from 1 (lowest priority) to 5 (highest possible priority). Default 
        value `-1` means XMRig doesn't change threads priority at all,

        Returns:
            int: Mining thread priority, or False if not available.
        """
        try:
            log.debug(self._backends_response[0]["priority"])
            return self._backends_response[0]["priority"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU priority data: {e}")
            return False

    @property
    def be_cpu_msr(self) -> bool | None:
        """
        Retrieves the cached CPU msr information from the backends data.

        Returns:
            bool: Bool representing msr information, or None if not available.
        """
        try:
            log.debug(self._backends_response[0]["msr"])
            return self._backends_response[0]["msr"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU msr data: {e}")
            return None

    @property
    def be_cpu_asm(self) -> str | bool:
        """
        Retrieves the cached CPU asm information from the backends data.

        Returns:
            str: ASM information, or False if not available.
        """
        try:
            log.debug(self._backends_response[0]["asm"])
            return self._backends_response[0]["asm"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU asm data: {e}")
            return False

    @property
    def be_cpu_argon2_impl(self) -> str | bool:
        """
        Retrieves the cached CPU argon2 implementation information from the backends data.

        Returns:
            str: Argon2 implementation information, or False if not available.
        """
        try:
            log.debug(self._backends_response[0]["argon2-impl"])
            return self._backends_response[0]["argon2-impl"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU argon2 implementation data: {e}")
            return False

    @property
    def be_cpu_hugepages(self) -> list | bool:
        """
        Retrieves the cached CPU hugepages information from the backends data.

        Returns:
            list: Hugepages information, or False if not available.
        """
        try:
            log.debug(self._backends_response[0]["hugepages"])
            return self._backends_response[0]["hugepages"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU hugepages data: {e}")
            return False

    @property
    def be_cpu_memory(self) -> int | bool:
        """
        Retrieves the cached CPU memory information from the backends data.

        Returns:
            int: Memory information, or False if not available.
        """
        try:
            log.debug(self._backends_response[0]["memory"])
            return self._backends_response[0]["memory"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU memory data: {e}")
            return False
    
    @property
    def be_cpu_hashrates(self) -> int | bool:
        """
        Retrieves the cached CPU hashrates information from the backends data.

        Returns:
            int: Hashrates information, or False if not available.
        """
        try:
            log.debug(self._backends_response[0]["hashrate"])
            return self._backends_response[0]["hashrate"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU hashrates data: {e}")
            return False
    
    @property
    def be_cpu_hashrate_10s(self) -> int | bool:
        """
        Retrieves the cached CPU hashrate (10s) information from the backends data.

        Returns:
            int: Hashrate (10s) information, or False if not available.
        """
        try:
            log.debug(self._backends_response[0]["hashrate"][0])
            return self._backends_response[0]["hashrate"][0]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU hashrate (10s) data: {e}")
            return False
    
    @property
    def be_cpu_hashrate_1m(self) -> int | bool:
        """
        Retrieves the cached CPU hashrate (1m) information from the backends data.

        Returns:
            int: Hashrate (1m) information, or False if not available.
        """
        try:
            log.debug(self._backends_response[0]["hashrate"][1])
            return self._backends_response[0]["hashrate"][1]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU hashrate (1m) data: {e}")
            return False
    
    @property
    def be_cpu_hashrate_15m(self) -> int | bool:
        """
        Retrieves the cached CPU hashrate (15m) information from the backends data.

        Returns:
            int: Hashrate (15m) information, or False if not available.
        """
        try:
            log.debug(self._backends_response[0]["hashrate"][2])
            return self._backends_response[0]["hashrate"][2]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU hashrate (15m) data: {e}")
            return False
    
    @property
    def be_cpu_threads(self) -> list | bool:
        """
        Retrieves the cached CPU threads information from the backends data.

        Returns:
            list: Threads information, or False if not available.
        """
        try:
            log.debug(self._backends_response[0]["threads"])
            return self._backends_response[0]["threads"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU threads data: {e}")
            return False

    @property
    def be_cpu_threads_intensity(self) -> list | bool:
        """
        Retrieves the cached CPU threads intensity information from the backends data.

        Returns:
            list: Threads intensity information, or False if not available.
        """
        intensities = []
        try:
            for i in self._backends_response[0]["threads"]:
                intensities.append(i["intensity"])
            log.debug(intensities)
            return intensities
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU threads intensity data: {e}")
            return False
    
    @property
    def be_cpu_threads_affinity(self) -> list | bool:
        """
        Retrieves the cached CPU threads affinity information from the backends data.

        Returns:
            list: Threads affinity information, or False if not available.
        """
        affinities = []
        try:
            for i in self._backends_response[0]["threads"]:
                affinities.append(i["affinity"])
            log.debug(affinities)
            return affinities
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU threads affinity data: {e}")
            return False
    
    @property
    def be_cpu_threads_av(self) -> list | bool:
        """
        Retrieves the cached CPU threads av information from the backends data.

        Returns:
            list: Threads av information, or False if not available.
        """
        avs = []
        try:
            for i in self._backends_response[0]["threads"]:
                avs.append(i["av"])
            log.debug(avs)
            return avs
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU threads av data: {e}")
            return False
    
    @property
    def be_cpu_threads_hashrates_10s(self) -> list | bool:
        """
        Retrieves the cached CPU threads hashrates (10s) information from the backends data.

        Returns:
            list: Threads hashrates (10s) information, or False if not available.
        """
        hashrates_10s = []
        try:
            for i in self._backends_response[0]["threads"]:
                hashrates_10s.append(i["hashrate"][0])
            log.debug(hashrates_10s)
            return hashrates_10s
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU threads hashrates (10s) data: {e}")
            return False
    
    @property
    def be_cpu_threads_hashrates_1m(self) -> list | bool:
        """
        Retrieves the cached CPU threads hashrates (1m) information from the backends data.

        Returns:
            list: Threads hashrates (1m) information, or False if not available.
        """
        hashrates_1m = []
        try:
            for i in self._backends_response[0]["threads"]:
                hashrates_1m.append(i["hashrate"][1])
            log.debug(hashrates_1m)
            return hashrates_1m
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU threads hashrates (1m) data: {e}")
            return False
    
    @property
    def be_cpu_threads_hashrates_15m(self) -> list | bool:
        """
        Retrieves the cached CPU threads hashrates (15m) information from the backends data.

        Returns:
            list: Threads hashrates (15m) information, or False if not available.
        """
        hashrates_15m = []
        try:
            for i in self._backends_response[0]["threads"]:
                hashrates_15m.append(i["hashrate"][0])
            log.debug(hashrates_15m)
            return hashrates_15m
        except Exception as e:
            log.error(f"An error occurred fetching the cached CPU threads hashrates (15m) data: {e}")
            return False

    @property
    def be_opencl_type(self) -> str | bool:
        """
        Retrieves the cached OpenCL type information from the backends data.

        Returns:
            str: Type information, or None if not available.
        """
        try:
            log.debug(self._backends_response[1]["type"])
            return self._backends_response[1]["type"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL type data: {e}")
            return None

    @property
    def be_opencl_enabled(self) -> bool | None:
        """
        Retrieves the cached OpenCL enabled information from the backends data.

        Returns:
            bool: Bool representing enabled information, or None if not available.
        """
        try:
            log.debug(self._backends_response[1]["enabled"])
            return self._backends_response[1]["enabled"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL enabled data: {e}")
            return None

    @property
    def be_opencl_algo(self) -> str | bool:
        """
        Retrieves the cached OpenCL algorithm information from the backends data.

        Returns:
            str: Algorithm information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["algo"])
            return self._backends_response[1]["algo"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL algorithm data: {e}")
            return False

    @property
    def be_opencl_profile(self) -> str | bool:
        """
        Retrieves the cached OpenCL profile information from the backends data.

        Returns:
            str: Profile information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["profile"])
            return self._backends_response[1]["profile"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL profile data: {e}")
            return False

    @property
    def be_opencl_platform(self) -> dict | bool:
        """
        Retrieves the cached OpenCL platform information from the backends data.

        Returns:
            dict: Platform information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["platform"])
            return self._backends_response[1]["platform"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL platform data: {e}")
            return False
    
    @property
    def be_opencl_platform_index(self) -> int | bool:
        """
        Retrieves the cached OpenCL platform index information from the backends data.

        Returns:
            int: Platform index information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["platform"]["index"])
            return self._backends_response[1]["platform"]["index"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL platform index data: {e}")
            return False
    
    @property
    def be_opencl_platform_profile(self) -> str | bool:
        """
        Retrieves the cached OpenCL platform profile information from the backends data.

        Returns:
            str: Platform profile information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["platform"]["profile"])
            return self._backends_response[1]["platform"]["profile"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL platform profile data: {e}")
            return False
    
    @property
    def be_opencl_platform_version(self) -> str | bool:
        """
        Retrieves the cached OpenCL platform version information from the backends data.

        Returns:
            str: Platform version information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["platform"]["version"])
            return self._backends_response[1]["platform"]["version"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL platform version data: {e}")
            return False
    
    @property
    def be_opencl_platform_name(self) -> str | bool:
        """
        Retrieves the cached OpenCL platform name information from the backends data.

        Returns:
            str: Platform name information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["platform"]["name"])
            return self._backends_response[1]["platform"]["name"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL platform name data: {e}")
            return False
    
    @property
    def be_opencl_platform_vendor(self) -> str | bool:
        """
        Retrieves the cached OpenCL platform vendor information from the backends data.

        Returns:
            str: Platform vendor information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["platform"]["vendor"])
            return self._backends_response[1]["platform"]["vendor"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL platform vendor data: {e}")
            return False
    
    @property
    def be_opencl_platform_extensions(self) -> str | bool:
        """
        Retrieves the cached OpenCL platform extensions information from the backends data.

        Returns:
            str: Platform extensions information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["platform"]["extensions"])
            return self._backends_response[1]["platform"]["extensions"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL platform extensions data: {e}")
            return False
    
    @property
    def be_opencl_hashrates(self) -> list | bool:
        """
        Retrieves the cached OpenCL hashrates information from the backends data.

        Returns:
            list: Hashrates information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["hashrate"])
            return self._backends_response[1]["hashrate"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL hashrates data: {e}")
            return False
    
    @property
    def be_opencl_hashrate_10s(self) -> int | bool:
        """
        Retrieves the cached OpenCL hashrate (10s) information from the backends data.

        Returns:
            int: Hashrate (10s) information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["hashrate"][0])
            return self._backends_response[1]["hashrate"][0]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL hashrate (10s) data: {e}")
            return False
    
    @property
    def be_opencl_hashrate_1m(self) -> int | bool:
        """
        Retrieves the cached OpenCL hashrate (1m) information from the backends data.

        Returns:
            int: Hashrate (1m) information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["hashrate"][1])
            return self._backends_response[1]["hashrate"][1]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL hashrate (1m) data: {e}")
            return False
    
    @property
    def be_opencl_hashrate_15m(self) -> int | bool:
        """
        Retrieves the cached OpenCL hashrate (15m) information from the backends data.

        Returns:
            int: Hashrate (15m) information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["hashrate"][2])
            return self._backends_response[1]["hashrate"][2]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL hashrate (15m) data: {e}")
            return False

    @property
    def be_opencl_threads(self) -> dict | bool:
        """
        Retrieves the cached OpenCL threads information from the backends data.

        Returns:
            dict: Threads information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0])
            return self._backends_response[1]["threads"][0]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads data: {e}")
            return False

    @property
    def be_opencl_threads_index(self) -> int | bool:
        """
        Retrieves the cached OpenCL threads index information from the backends data.

        Returns:
            int: Threads index information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["index"])
            return self._backends_response[1]["threads"][0]["index"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads index data: {e}")
            return False
    
    @property
    def be_opencl_threads_intensity(self) -> int | bool:
        """
        Retrieves the cached OpenCL threads intensity information from the backends data.

        Returns:
            int: Threads intensity information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["intensity"])
            return self._backends_response[1]["threads"][0]["intensity"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads intensity data: {e}")
            return False
    
    @property
    def be_opencl_threads_worksize(self) -> int | bool:
        """
        Retrieves the cached OpenCL threads worksize information from the backends data.

        Returns:
            int: Threads worksize information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["worksize"])
            return self._backends_response[1]["threads"][0]["worksize"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads worksize data: {e}")
            return False
    
    @property
    def be_opencl_threads_amount(self) -> list | bool:
        """
        Retrieves the cached OpenCL threads amount information from the backends data.

        Returns:
            list: Threads amount information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["threads"])
            return self._backends_response[1]["threads"][0]["threads"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads amount data: {e}")
            return False
    
    @property
    def be_opencl_threads_unroll(self) -> int | bool:
        """
        Retrieves the cached OpenCL threads unroll information from the backends data.

        Returns:
            int: Threads unroll information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["unroll"])
            return self._backends_response[1]["threads"][0]["unroll"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads unroll data: {e}")
            return False
    
    @property
    def be_opencl_threads_affinity(self) -> int | bool:
        """
        Retrieves the cached OpenCL threads affinity information from the backends data.

        Returns:
            int: Threads affinity information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["affinity"])
            return self._backends_response[1]["threads"][0]["affinity"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads affinity data: {e}")
            return False
    
    @property
    def be_opencl_threads_hashrates(self) -> list | bool:
        """
        Retrieves the cached OpenCL threads hashrates information from the backends data.

        Returns:
            list: Threads hashrates information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["hashrate"])
            return self._backends_response[1]["threads"][0]["hashrate"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads hashrates data: {e}")
            return False
    
    @property
    def be_opencl_threads_hashrates_10s(self) -> int | bool:
        """
        Retrieves the cached OpenCL threads hashrates (10s) information from the backends data.

        Returns:
            int: Threads hashrates (10s) information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["hashrate"][0])
            return self._backends_response[1]["threads"][0]["hashrate"][0]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads hashrates (10s) data: {e}")
            return False
    
    @property
    def be_opencl_threads_hashrates_1m(self) -> int | bool:
        """
        Retrieves the cached OpenCL threads hashrates (1m) information from the backends data.

        Returns:
            int: Threads hashrates (1m) information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["hashrate"][1])
            return self._backends_response[1]["threads"][0]["hashrate"][1]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads hashrates (1m) data: {e}")
            return False
    
    @property
    def be_opencl_threads_hashrates_15m(self) -> int | bool:
        """
        Retrieves the cached OpenCL threads hashrates (15m) information from the backends data.

        Returns:
            int: Threads hashrates (15m) information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["hashrate"][2])
            return self._backends_response[1]["threads"][0]["hashrate"][2]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads hashrates (15m) data: {e}")
            return False
    
    @property
    def be_opencl_threads_board(self) -> str | bool:
        """
        Retrieves the cached OpenCL threads board information from the backends data.

        Returns:
            str: Threads board information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["board"])
            return self._backends_response[1]["threads"][0]["board"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads board data: {e}")
            return False
    
    @property
    def be_opencl_threads_name(self) -> str | bool:
        """
        Retrieves the cached OpenCL threads name information from the backends data.

        Returns:
            str: Threads name information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["name"])
            return self._backends_response[1]["threads"][0]["name"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads name data: {e}")
            return False
    
    @property
    def be_opencl_threads_bus_id(self) -> str | bool:
        """
        Retrieves the cached OpenCL threads bus ID information from the backends data.

        Returns:
            str: Threads bus ID information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["bus_id"])
            return self._backends_response[1]["threads"][0]["bus_id"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads bus ID data: {e}")
            return False
    
    @property
    def be_opencl_threads_cu(self) -> int | bool:
        """
        Retrieves the cached OpenCL threads cu information from the backends data.

        Returns:
            int: Threads cu information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["cu"])
            return self._backends_response[1]["threads"][0]["cu"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads cu data: {e}")
            return False
    
    @property
    def be_opencl_threads_global_mem(self) -> int | bool:
        """
        Retrieves the cached OpenCL threads global memory information from the backends data.

        Returns:
            int: Threads global memory information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["global_mem"])
            return self._backends_response[1]["threads"][0]["global_mem"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads global memory data: {e}")
            return False
    
    @property
    def be_opencl_threads_health(self) -> dict | bool:
        """
        Retrieves the cached OpenCL threads health information from the backends data.

        Returns:
            dict: Threads health information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["health"])
            return self._backends_response[1]["threads"][0]["health"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads health data: {e}")
            return False
    
    @property
    def be_opencl_threads_health_temp(self) -> int | bool:
        """
        Retrieves the cached OpenCL threads health temperature information from the backends data.

        Returns:
            int: Threads health temperature information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["health"]["temperature"])
            return self._backends_response[1]["threads"][0]["health"]["temperature"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads health temperature data: {e}")
            return False
    
    @property
    def be_opencl_threads_health_power(self) -> int | bool:
        """
        Retrieves the cached OpenCL threads health power information from the backends data.

        Returns:
            int: Threads health power information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["health"]["power"])
            return self._backends_response[1]["threads"][0]["health"]["power"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads health power data: {e}")
            return False
    
    @property
    def be_opencl_threads_health_clock(self) -> int | bool:
        """
        Retrieves the cached OpenCL threads health clock information from the backends data.

        Returns:
            int: Threads health clock information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["health"]["clock"])
            return self._backends_response[1]["threads"][0]["health"]["clock"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads health clock data: {e}")
            return False
    
    @property
    def be_opencl_threads_health_mem_clock(self) -> int | bool:
        """
        Retrieves the cached OpenCL threads health memory clock information from the backends data.

        Returns:
            int: Threads health memory clock information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["health"]["mem_clock"])
            return self._backends_response[1]["threads"][0]["health"]["mem_clock"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads health memory clock data: {e}")
            return False
    
    @property
    def be_opencl_threads_health_rpm(self) -> int | bool:
        """
        Retrieves the cached OpenCL threads health rpm information from the backends data.

        Returns:
            int: Threads health rpm information, or False if not available.
        """
        try:
            log.debug(self._backends_response[1]["threads"][0]["health"]["rpm"])
            return self._backends_response[1]["threads"][0]["health"]["rpm"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached OpenCL threads health rpm data: {e}")
            return False

    @property
    def be_cuda_type(self) -> str | bool:
        """
        Retrieves the cached Cuda current type info from the backends data.

        Returns:
            str: Type info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["type"])
            return self._backends_response[2]["type"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda type data: {e}")
            return False

    @property
    def be_cuda_enabled(self) -> bool | None:
        """
        Retrieves the cached Cuda current enabled info from the backends data.

        Returns:
            bool: Current enabled status, or None if not available.
        """
        try:
            log.debug(self._backends_response[2]["enabled"])
            return self._backends_response[2]["enabled"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda enabled status data: {e}")
            return None

    @property
    def be_cuda_algo(self) -> str | bool:
        """
        Retrieves the cached Cuda algorithm information from the backends data.

        Returns:
            str: Algorithm information, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["algo"])
            return self._backends_response[2]["algo"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda algorithm data: {e}")
            return False

    @property
    def be_cuda_profile(self) -> str | bool:
        """
        Retrieves the cached Cuda profile information from the backends data.

        Returns:
            str: Profile information, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["profile"])
            return self._backends_response[2]["profile"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda profile data: {e}")
            return False

    @property
    def be_cuda_versions(self) -> dict | bool:
        """
        Retrieves the cached Cuda versions information from the backends data.

        Returns:
            dict: Cuda versions information, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["versions"])
            return self._backends_response[2]["versions"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda versions data: {e}")
            return False

    @property
    def be_cuda_runtime(self) -> str | bool:
        """
        Retrieves the cached Cuda runtime information from the backends data.

        Returns:
           str: Cuda runtime information, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["versions"]["cuda-runtime"])
            return self._backends_response[2]["versions"]["cuda-runtime"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda runtime data: {e}")
            return False

    @property
    def be_cuda_driver(self) -> str | bool:
        """
        Retrieves the cached Cuda driver information from the backends data.

        Returns:
            str: Cuda driver information, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["versions"]["cuda-driver"])
            return self._backends_response[2]["versions"]["cuda-driver"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda driver data: {e}")
            return False

    @property
    def be_cuda_plugin(self) -> str | bool:
        """
        Retrieves the cached Cuda plugin information from the backends data.

        Returns:
            str: Cuda plugin information, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["versions"]["plugin"])
            return self._backends_response[2]["versions"]["plugin"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda plugin data: {e}")
            return False

    @property
    def be_cuda_hashrates(self) -> list | bool:
        """
        Retrieves the cached Cuda current hashrates info from the backends data.

        Returns:
            list: Hashrates info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["hashrate"])
            return self._backends_response[2]["hashrate"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda current hashrates data: {e}")
            return False

    @property
    def be_cuda_hashrate_10s(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (10s) info from the backends data.

        Returns:
           int: Hashrate (10s) info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["hashrate"][0])
            return self._backends_response[2]["hashrate"][0]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda current hashrate (10s) data: {e}")
            return False

    @property
    def be_cuda_hashrate_1m(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (1m) info from the backends data.

        Returns:
            int: Hashrate (1m) info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["hashrate"][1])
            return self._backends_response[2]["hashrate"][1]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda current hashrate (1m) data: {e}")
            return False

    @property
    def be_cuda_hashrate_15m(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (15m) info from the backends data.

        Returns:
            int: Hashrate (15m) info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["hashrate"][2])
            return self._backends_response[2]["hashrate"][2]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda current hashrate (15m) data: {e}")
            return False

    @property
    def be_cuda_threads(self) -> dict | bool:
        """
        Retrieves the cached Cuda current threads info from the backends data.

        Returns:
            dict: Threads info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0])
            return self._backends_response[2]["threads"][0]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads data: {e}")
            return False

    @property
    def be_cuda_threads_index(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads index info from the backends data.

        Returns:
            int: Threads index info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["index"])
            return self._backends_response[2]["threads"][0]["index"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads index data: {e}")
            return False

    @property
    def be_cuda_threads_amount(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads amount info from the backends data.

        Returns:
            int: Threads amount info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["threads"])
            return self._backends_response[2]["threads"][0]["threads"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads amount data: {e}")
            return False

    @property
    def be_cuda_threads_blocks(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads blocks info from the backends data.

        Returns:
            int: Threads blocks info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["blocks"])
            return self._backends_response[2]["threads"][0]["blocks"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads blocks data: {e}")
            return False

    @property
    def be_cuda_threads_bfactor(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads bfactor info from the backends data.

        Returns:
            int: Threads bfactor info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["bfactor"])
            return self._backends_response[2]["threads"][0]["bfactor"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads bfactor data: {e}")
            return False

    @property
    def be_cuda_threads_bsleep(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads bsleep info from the backends data.

        Returns:
            int: Threads bsleep info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["bsleep"])
            return self._backends_response[2]["threads"][0]["bsleep"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads bsleep data: {e}")
            return False

    @property
    def be_cuda_threads_affinity(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads affinity info from the backends data.

        Returns:
            int: Threads affinity info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["affinity"])
            return self._backends_response[2]["threads"][0]["affinity"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads affinity data: {e}")
            return False

    @property
    def be_cuda_threads_dataset_host(self) -> bool | None:
        """
        Retrieves the cached Cuda current threads dataset host info from the backends data.

        Returns:
            bool: Threads dataset host info, or None if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["dataset_host"])
            return self._backends_response[2]["threads"][0]["dataset_host"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads dataset host data: {e}")
            return None

    @property
    def be_cuda_threads_hashrates(self) -> list | bool:
        """
        Retrieves the cached Cuda current hashrates (10s/1m/15m) from the summary data.

        Returns:
            list: Hashrates, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["hashrate"])
            return self._backends_response[2]["threads"][0]["hashrate"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads hashrates data: {e}")
            return False

    @property
    def be_cuda_threads_hashrate_10s(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (10s) from the summary data.

        Returns:
            int: Hashrate (10s), or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["hashrate"][0])
            return self._backends_response[2]["threads"][0]["hashrate"][0]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads hashrate (10s) data: {e}")
            return False

    @property
    def be_cuda_threads_hashrate_1m(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (1m) from the summary data.

        Returns:
            int: Hashrate (1m), or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["hashrate"][1])
            return self._backends_response[2]["threads"][0]["hashrate"][1]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads hashrates (1m) data: {e}")
            return False

    @property
    def be_cuda_threads_hashrate_15m(self) -> int | bool:
        """
        Retrieves the cached Cuda current hashrate (15m) from the summary data.

        Returns:
            int: Hashrate (15m), or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["hashrate"][2])
            return self._backends_response[2]["threads"][0]["hashrate"][2]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads hashrates (15m) data: {e}")
            return False

    @property
    def be_cuda_threads_name(self) -> str | bool:
        """
        Retrieves the cached Cuda current threads name info from the backends data.

        Returns:
            str: Threads name info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["name"])
            return self._backends_response[2]["threads"][0]["name"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads name data: {e}")
            return False

    @property
    def be_cuda_threads_bus_id(self) -> str | bool:
        """
        Retrieves the cached Cuda current threads bus ID info from the backends data.

        Returns:
            str: Threads bus ID info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["bus_id"])
            return self._backends_response[2]["threads"][0]["bus_id"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads bus ID data: {e}")
            return False

    @property
    def be_cuda_threads_smx(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads smx info from the backends data.

        Returns:
            int: Threads smx info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["smx"])
            return self._backends_response[2]["threads"][0]["smx"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads smx data: {e}")
            return False

    @property
    def be_cuda_threads_arch(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads arch info from the backends data.

        Returns:
            int: Threads arch info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["arch"])
            return self._backends_response[2]["threads"][0]["arch"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads arch data: {e}")
            return False

    @property
    def be_cuda_threads_global_mem(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads global memory info from the backends data.

        Returns:
            int: Threads global mem info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["global_mem"])
            return self._backends_response[2]["threads"][0]["global_mem"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads global memory data: {e}")
            return False

    @property
    def be_cuda_threads_clock(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads clock info from the backends data.

        Returns:
            int: Threads clock info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["clock"])
            return self._backends_response[2]["threads"][0]["clock"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads clock info data: {e}")
            return False

    @property
    def be_cuda_threads_memory_clock(self) -> int | bool:
        """
        Retrieves the cached Cuda current threads memory clock info from the backends data.

        Returns:
            int: Threads memory clock info, or False if not available.
        """
        try:
            log.debug(self._backends_response[2]["threads"][0]["memory_clock"])
            return self._backends_response[2]["threads"][0]["memory_clock"]
        except Exception as e:
            log.error(f"An error occurred fetching the cached Cuda threads memory clock data: {e}")
            return False

import requests
from datetime import timedelta

class XMRigAuthorizationError(Exception):
    def __init__(self, message="Access token is required but not provided. Please provide a valid access token."):
        self.message = message
        super().__init__(self.message)

class XMRigAPIPortError(Exception):
    def __init__(self, port):
        super().__init__(f"Unable to connect to XMRig API! {port} is not a valid port!")

class XMRig:
    def __init__(self, xmrig_path, config_path, http_api_port:int=None, http_api_token:str=None):
        self._xmrig_path = xmrig_path
        self._config_path = config_path
        self._http_api_port = http_api_port
        self._http_api_token = http_api_token

        if self._http_api_port is not None:
            if self._http_api_port < 0 or self._http_api_port > 65535:
                raise XMRigAPIPortError(port=self.http_api_port)

            if self._http_api_token is not None:
                self.API = XMRigAPI("127.0.0.1", self._http_api_port, self._http_api_token)
            else:
                self.API = XMRigAPI("127.0.0.1", self._http_api_port)

class XMRigAPI:
    """
    A class to interact with the XMRig miner API.

    Attributes:
        _ip (str): IP address of the XMRig API.
        _port (int): Port of the XMRig API.
        _access_token (str): Access token for authorization.
        _base_url (str): Base URL for the XMRig API.
        _summary_url (str): URL for the summary endpoint.
        _hashrate (float): Cached hashrate value.
        _uptime (int): Cached uptime value.
        _accepted_jobs (int): Cached number of accepted jobs.
        _rejected_jobs (int): Cached number of rejected jobs.
        _paused (bool): Cached paused status of the miner.
    """

    def __init__(self, ip, port, access_token: str = None):
        """
        Initializes the XMRig instance with the provided IP, port, and access token.

        Args:
            ip (str): IP address of the XMRig API.
            port (int): Port of the XMRig API.
            access_token (str, optional): Access token for authorization. Defaults to None.
        """
        self._ip = ip
        self._port = port
        self._access_token = access_token
        self._base_url = f"http://{ip}:{port}/2"
        self._summary_url = f"{self._base_url}/summary"
        self._hashrate = None
        self._uptime = None
        self._accepted_jobs = None
        self._rejected_jobs = None
        self._paused = None

    def _get_headers(self):
        """
        Constructs the headers for the HTTP requests, including the authorization token if provided.

        Returns:
            dict: Headers for the HTTP request.
        """
        headers = {}
        if self._access_token:
            headers['Authorization'] = f"Bearer {self._access_token}"
        return headers

    def fetch_summary(self):
        """
        Fetches the summary data from the XMRig API.

        Returns:
            dict: Parsed JSON response from the summary endpoint, or None if an error occurred.
        """
        headers = self._get_headers()
        try:
            response = requests.get(self._summary_url, headers=headers)
            if response.status_code == 401:
                raise XMRigAuthorizationError()
            response.raise_for_status()  # Raise an HTTPError for bad responses (4xx and 5xx)
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while connecting to {self._summary_url}: {e}")
            return None

    def pause_miner(self):
        """
        Pauses the miner.

        Returns:
            bool: True if the miner was successfully paused, False otherwise.
        """
        headers = self._get_headers()
        try:
            response = requests.post(self._pause_url, headers=headers)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            return False

    def resume_miner(self):
        """
        Resumes the miner.

        Returns:
            bool: True if the miner was successfully resumed, False otherwise.
        """
        headers = self._get_headers()
        try:
            response = requests.post(self._resume_url, headers=headers)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            return False

    def restart_miner(self):
        """
        Restarts the miner.

        Returns:
            bool: True if the miner was successfully restarted, False otherwise.
        """
        headers = self._get_headers()
        try:
            response = requests.post(self._restart_url, headers=headers)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            return False

    def stop_miner(self):
        """
        Stops the miner.

        Returns:
            bool: True if the miner was successfully stopped, False otherwise.
        """
        headers = self._get_headers()
        try:
            response = requests.post(self._stop_url, headers=headers)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            return False

    @property
    def hashrate(self):
        """
        Retrieves the current hashrate from the summary data.

        Returns:
            float: Current hashrate, or None if not available.
        """
        summary = self.fetch_summary()
        if summary and "hashrate" in summary:
            self._hashrate = summary["hashrate"]["total"][0]
        return self._hashrate

    @property
    def uptime(self):
        """
        Retrieves the current uptime from the summary data.

        Returns:
            int: Current uptime in seconds, or None if not available.
        """
        summary = self.fetch_summary()
        if summary and "uptime" in summary:
            self._uptime = summary["uptime"]
        return self._uptime

    @property
    def accepted_jobs(self):
        """
        Retrieves the number of accepted jobs from the summary data.

        Returns:
            int: Number of accepted jobs, or None if not available.
        """
        summary = self.fetch_summary()
        if summary and "connection" in summary:
            self._accepted_jobs = summary["connection"]["accepted"]
        return self._accepted_jobs

    @property
    def rejected_jobs(self):
        """
        Retrieves the number of rejected jobs from the summary data.

        Returns:
            int: Number of rejected jobs, or None if not available.
        """
        summary = self.fetch_summary()
        if summary and "connection" in summary:
            self._rejected_jobs = summary["connection"]["rejected"]
        return self._rejected_jobs

    @property
    def miner_paused(self):
        """
        Retrieves the paused status of the miner from the summary data.

        Returns:
            bool: True if the miner is paused, False otherwise, or None if not available.
        """
        summary = self.fetch_summary()
        if summary and "paused" in summary:
            self._paused = summary["paused"]
        return self._paused

    @property
    def total_hashes(self):
        """
        Retrieves the total number of hashes from the summary data.

        Returns:
            int: Total number of hashes, or None if not available.
        """
        summary = self.fetch_summary()
        if summary and "results" in summary:
            return summary["results"]["hashes_total"]
        return None

    @property
    def current_difficulty(self):
        """
        Retrieves the current difficulty from the summary data.

        Returns:
            int: Current difficulty, or None if not available.
        """
        summary = self.fetch_summary()
        if summary and "results" in summary:
            return summary["results"]["diff_current"]
        return None

    @property
    def pool_info(self):
        """
        Retrieves the pool information from the summary data.

        Returns:
            dict: Pool information, or None if not available.
        """
        summary = self.fetch_summary()
        if summary and "connection" in summary:
            return summary["connection"]["pool"]
        return None

    @property
    def cpu_info(self):
        """
        Retrieves the CPU information from the summary data.

        Returns:
            dict: CPU information, or None if not available.
        """
        summary = self.fetch_summary()
        if summary and "cpu" in summary:
            return summary["cpu"]
        return None

    @property
    def version(self):
        """
        Retrieves the version information from the summary data.

        Returns:
            str: Version information, or None if not available.
        """
        summary = self.fetch_summary()
        if summary and "version" in summary:
            return summary["version"]
        return None

    @property
    def uptime_readable(self):
        """
        Retrieves the uptime in a human-readable format from the summary data.

        Returns:
            str: Uptime in the format "days, hours:minutes:seconds", or None if not available.
        """
        summary = self.fetch_summary()
        if summary and "uptime" in summary:
            return str(timedelta(seconds=summary["uptime"]))
        return None

    @property
    def memory_usage(self):
        """
        Retrieves the memory usage from the summary data.

        Returns:
            dict: Memory usage information, or None if not available.
        """
        summary = self.fetch_summary()
        if summary and "resources" in summary and "memory" in summary["resources"]:
            return summary["resources"]["memory"]
        return None

    @property
    def load_average(self):
        """
        Retrieves the load average from the summary data.

        Returns:
            list: Load average information, or None if not available.
        """
        summary = self.fetch_summary()
        if summary and "resources" in summary and "load_average" in summary["resources"]:
            return summary["resources"]["load_average"]
        return None

    @property
    def algorithm(self):
        """
        Retrieves the current mining algorithm from the summary data.

        Returns:
            str: Current mining algorithm, or None if not available.
        """
        summary = self.fetch_summary()
        if summary and "algo" in summary:
            return summary["algo"]
        return None

import requests
from datetime import timedelta


class XMRigAuthorizationError(Exception):
    """Custom exception to handle XMRig authorization errors."""

    def __init__(self, message="Access token is required but not provided. Please provide a valid access token."):
        self.message = message
        super().__init__(self.message)


class XMRig:
    def __init__(self, ip, port, access_token: str = None):
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
        headers = {}
        if self._access_token:
            headers['Authorization'] = f"Bearer {self._access_token}"
        return headers

    def fetch_summary(self):
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

    @property
    def hashrate(self):
        summary = self.fetch_summary()
        if summary and "hashrate" in summary:
            self._hashrate = summary["hashrate"]["total"][0]
        return self._hashrate

    @property
    def uptime(self):
        summary = self.fetch_summary()
        if summary and "uptime" in summary:
            self._uptime = summary["uptime"]
        return self._uptime

    @property
    def accepted_jobs(self):
        summary = self.fetch_summary()
        if summary and "connection" in summary:
            self._accepted_jobs = summary["connection"]["accepted"]
        return self._accepted_jobs

    @property
    def rejected_jobs(self):
        summary = self.fetch_summary()
        if summary and "connection" in summary:
            self._rejected_jobs = summary["connection"]["rejected"]
        return self._rejected_jobs

    @property
    def paused(self):
        summary = self.fetch_summary()
        if summary and "paused" in summary:
            self._paused = summary["paused"]
        return self._paused

    @property
    def total_hashes(self):
        summary = self.fetch_summary()
        if summary and "results" in summary:
            return summary["results"]["hashes_total"]
        return None

    @property
    def current_difficulty(self):
        summary = self.fetch_summary()
        if summary and "results" in summary:
            return summary["results"]["diff_current"]
        return None

    @property
    def pool_info(self):
        summary = self.fetch_summary()
        if summary and "connection" in summary:
            return summary["connection"]["pool"]
        return None

    @property
    def cpu_info(self):
        summary = self.fetch_summary()
        if summary and "cpu" in summary:
            return summary["cpu"]
        return None

    @property
    def version(self):
        summary = self.fetch_summary()
        if summary and "version" in summary:
            return summary["version"]
        return None

    @property
    def uptime_readable(self):
        summary = self.fetch_summary()
        if summary and "uptime" in summary:
            return str(timedelta(seconds=summary["uptime"]))
        return None

    @property
    def memory_usage(self):
        summary = self.fetch_summary()
        if summary and "resources" in summary and "memory" in summary["resources"]:
            return summary["resources"]["memory"]
        return None

    @property
    def load_average(self):
        summary = self.fetch_summary()
        if summary and "resources" in summary and "load_average" in summary["resources"]:
            return summary["resources"]["load_average"]
        return None
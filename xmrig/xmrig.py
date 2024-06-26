import requests


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
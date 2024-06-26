class XMRig:
    def __init__(self, ip, port, access_token: str = None):
        self._ip = ip
        self._port = port
        self._access_token = access_token

        self._base_url = f"http://{ip}:{port}/2"
        self._summary_url = f"{self._base_url}/summary"
        self._stats_url = f"{self._base_url}/stats"
        self._config_url = f"{self._base_url}/config"
        self._version_url = f"{self._base_url}/version"
        self._log_url = f"{self._base_url}/log"
        self._backends_url = f"{self._base_url}/backends"
        self._workers_url = f"{self._base_url}/workers"
        self._results_url = f"{self._base_url}/results"
        self._connections_url = f"{self._base_url}/connections"
        self._threads_url = f"{self._base_url}/threads"

    def _format_summary(self, summary):
        formatted_summary = {
            "ID": summary.get("id"),
            "Worker ID": summary.get("worker_id"),
            "Uptime (seconds)": summary.get("uptime"),
            "Restricted": summary.get("restricted"),
            "Memory": summary.get("resources", {}).get("memory", {}),
            "Load Average": summary.get("resources", {}).get("load_average"),
            "Hardware Concurrency": summary.get("resources", {}).get("hardware_concurrency"),
            "Features": summary.get("features"),
            "Results": summary.get("results"),
            "Algorithm": summary.get("algo"),
            "Connection": summary.get("connection"),
            "Version": summary.get("version"),
            "Kind": summary.get("kind"),
            "User Agent": summary.get("ua"),
            "CPU": summary.get("cpu"),
            "Donate Level": summary.get("donate_level"),
            "Paused": summary.get("paused"),
            "Algorithms": summary.get("algorithms"),
            "Hashrate": summary.get("hashrate"),
            "Hugepages": summary.get("hugepages")
        }
        return formatted_summary


    @property
    def hashrate(self):
        summary = self.fetch_summary()
        if summary and "Hashrate" in summary:
            self._hashrate = summary["Hashrate"]["total"][0]
        return self._hashrate

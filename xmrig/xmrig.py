import os
import random, requests
import subprocess
from enum import Enum
from datetime import timedelta

class XMRigAuthorizationError(Exception):
    def __init__(self, message="Access token is required but not provided. Please provide a valid access token."):
        self.message = message
        super().__init__(self.message)

class XMRigAPIPortError(Exception):
    def __init__(self, port):
        super().__init__(f"Unable to connect to XMRig API! {port} is not a valid port!")

class XMRigPoolError(Exception):
    def __init__(self, message):
        super().__init__(message)

class PoolCoin(Enum):
    MONERO = "monero"
    WOWNERO = "wownero"
    LOKI = "loki"
    ARQMA = "arqma"
    MASARI = "masari"
    ITALO = "italo"
    GRIN = "grin"
    HAVEN = "haven"
    TURTLECOIN = "turtlecoin"
    BITTUBE = "bittube"
    FREEHAVEN = "freehaven"
    GRAFT = "graft"
    ULTRONIUM = "ultronium"
    KRB = "krb"  # Karbo
    NERVA = "nerva"
    Saronite = "saronite"
    Torque = "torque"

class PoolAlgorithm(Enum):
    RX_0 = "rx/0"  # RandomX default
    RX_WOW = "rx/wow"  # RandomX WowNero
    RX_LUA = "rx/lua"  # RandomX Lua
    RX_ARQ = "rx/arq"  # RandomX ArQmA
    RX_SFX = "rx/sfx"  # RandomX Safex
    RX_XLA = "rx/xla"  # RandomX Scala
    CN_0 = "cn/0"  # CryptoNight default (CNv0)
    CN_1 = "cn/1"  # CryptoNight variant 1 (CNv1)
    CN_FAST = "cn/fast"  # CryptoNight variant 2 (CNv2, aka CNFast)
    CN_HEAVY = "cn/heavy"  # CryptoNight Heavy
    CN_PICO = "cn/pico"  # CryptoNight Pico
    CN_HALF = "cn/half"  # CryptoNight Half
    CN_GPU = "cn/gpu"  # CryptoNight GPU
    CN_R = "cn/r"  # CryptoNight R
    CN_RWZ = "cn/rwz"  # CryptoNight ReverseWaltz
    CN_ZLS = "cn/zls"  # CryptoNight ZLS
    CN_DOUBLE = "cn/double"  # CryptoNight Double
    CN_CCX = "cn/ccx"  # CryptoNight Conceal
    CN_XAO = "cn/xao"  # CryptoNight Alloy
    CN_TRTL = "cn/trtl"  # CryptoNight Turtle
    CN_HAVEN = "cn/haven"  # CryptoNight Haven
    CN_TUBE = "cn/tube"  # CryptoNight BitTube
    CN_MSR = "cn/msr"  # CryptoNight Masari
    CN_GR = "cn/gr"  # CryptoNight Graft
    CN_RTO = "cn/rto"  # CryptoNight Rito

class XMRigPool():
    def __init__(self, coin:PoolCoin, algorithm:PoolAlgorithm, url:str, user:str, port:int=3333, password:str="x", tls:bool=False, keep_alive:bool=True, nice_hash:bool=False):
        self.coin = coin
        self.algo = algorithm.value
        self.url = url
        self.port = port
        self.user = user
        self.password = password
        self.tls = tls
        self.keep_alive = keep_alive
        self.nice_hash = nice_hash

class XMRig:
    def __init__(self, config_path:str=None, xmrig_path:str="xmrig", http_api_port:int=random.randint(1, 65535), http_api_token:str=None, donate_level:int=5, api_worker_id:str=None, http_api_host:str="0.0.0.0", opencl_enabled:bool=False, cuda_enabled:bool=False, pools:list=None):
        self._xmrig_path = xmrig_path
        self._config_path = config_path
        self._http_api_port = http_api_port
        self._http_api_token = http_api_token
        self._donate_level = donate_level
        self._api_worker_id = api_worker_id
        self._http_api_host = http_api_host
        self._opencl_enabled = opencl_enabled
        self._cuda_enabled = cuda_enabled
        self._pools = pools

        print(self._generate_execution_command())

        if self._http_api_port is not None:
            if self._http_api_port < 0 or self._http_api_port > 65535:
                raise XMRigAPIPortError(port=self.http_api_port)

            if self._http_api_token is not None:
                self.API = XMRigAPI("127.0.0.1", self._http_api_port, self._http_api_token)
            else:
                self.API = XMRigAPI("127.0.0.1", self._http_api_port)

        for x in pools:
            if type(x) is not XMRigPool:
                raise TypeError(f"Pool {x} must be a XMRigPool instance!")

    def _generate_execution_command(self):
        cmd = f"{self._xmrig_path} --donate-level {self._donate_level} --api-worker-id {self._api_worker_id} --http-host {self._http_api_host} --http-port {self._http_api_port}"

        if self._http_api_token is not None:
            cmd += f" --http-access-token {self._http_api_token}"

        if self._opencl_enabled:
            cmd += " --opencl"

        if self._cuda_enabled:
            cmd += " --cuda"

        for x in self._pools:
            cmd += f" -o {x.url}:{x.port} -u {x.user} -p {x.password}"
            if x.tls:
                cmd += " --tls"
            if x.keep_alive:
                cmd += " -k"
            if x.nice_hash:
                cmd += " --nicehash"
            cmd += f" --coin {x.coin.value} -a {x.algo}"

        return cmd

    def start_xmrig(self):
        if self._config_path is not None:
            subprocess.Popen(self._generate_execution_command())
        else:
            subprocess.Popen(f"{self._xmrig_path} -c {self._config_path}")
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

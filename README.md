# xmrig-python
[![PyPi](https://img.shields.io/badge/PyPi-1.1.1-green?labelColor=026ab5&style=flat-square&logo=pypi&logoColor=ffffff&link=https://pypi.org/project/xmrig/)](https://pypi.org/project/xmrig/)
[![Python](https://img.shields.io/badge/Python-%203.9,%203.10,%203.11,%203.12-green?labelColor=026ab5&style=flat-square&logo=pypi&logoColor=ffffff&link=https://pypi.org/project/xmrig/)](https://pypi.org/project/xmrig/)
![PyPI - Downloads](https://img.shields.io/pypi/dm/xmrig?label=PyPI%20Downloads)
![License](https://img.shields.io/github/license/CoulterStutz/python-xmrig?label=License&color=brightgreen)

A wrapper for the XMRig HTTP API and client manager

## Installing xmrig-python

### From Source

```shell
git clone https://github.com/CoulterStutz/python-xmrig.git && cd python-xmrig
poetry install # or use `pip install .`, dont forget the period to set the source location to the current directory.
```

### Using PyPi

```shell
poetry install xmrig # or use `pip install xmrig`.
```

After that the package will be available to use!

## Example Usage

Here is a basic implementation of the API Wrapper now dubbed XMRigAPI.

```python
import xmrig, logging
x = xmrig.XMRigAPI(ip="127.0.0.1", port="5555", access_token="example")
logging.basicConfig()
logging.getLogger("XMRigAPI").setLevel(logging.INFO)            # Change to DEBUG to print out all responses when their methods are called
log = logging.getLogger("MyLOG")

# Control the miner using JSON RPC.
x.pause_miner()
x.resume_miner()
x.stop_miner()
x.start_miner()

# Update cached data from endpoints individually or all at once
x.update_summary()
x.update_all_responses()

# Edit and update the miners `config.json` via the HTTP API.
x.update_config()                                               # This updates the cached data
config = x.config()                                             # Use the `config` property to access the data
config["pools"]["USER"] = "NEW_WALLET_ADDRESS"
x.post_config(config)

# Summary and Backends API data is available as properties in either full or individual format.
log.info(x.summary)                                             # Prints the entire `summary` endpoint response
log.info(x.sum_hashrates)                                       # Prints out the current hashrates
log.info(x.sum_pool_accepted_jobs)                              # Prints out the accepted_jobs counter
log.info(x.sum_pool_rejected_jobs)                              # Prints out the rejected_jobs counter
log.info(x.sum_current_difficulty)                              # Prints out the current difficulty
```
# xmrig-python
[![PyPi](https://img.shields.io/badge/PyPi-1.1-green?labelColor=026ab5&style=flat-square&logo=pypi&logoColor=ffffff&link=https://pypi.org/project/xmrig/)](https://pypi.org/project/xmrig/)
[![Python](https://img.shields.io/badge/Python-%203.9,%203.10,%203.11,%203.12-green?labelColor=026ab5&style=flat-square&logo=pypi&logoColor=ffffff&link=https://pypi.org/project/xmrig/)](https://pypi.org/project/xmrig/)
![PyPI - Downloads](https://img.shields.io/pypi/dm/xmrig?label=PyPI%20Downloads)
![License](https://img.shields.io/github/license/CoulterStutz/python-xmrig?label=License&color=brightgreen)

A wrapper for the XMRig HTTP API and client manager

## Installing xmrig-python
### Building From Source
```shell
git clone https://github.com/CoulterStutz/python-xmrig.git && cd python-xmrig
```
After installing from source, use poetry to install the package
```shell
poetry install
```
After that the package will be avalible to use!

### Using Pip or Poetry
#### Using Pip
```shell
pip install xmrig
```
#### Poetry
```shell
poetry install xmrig
```

## Example Usage
Here is a basic implementation of the API Wrapper now dubbed XMRigAPI in 1.1
```python
import xmrig
x = xmrig.XMRigAPI(ip="127.0.0.1", port="5545", access_token="example")
print(x.hashrate)  # Prints out the current hashrate
print(x.accepted_jobs)  # Prints out the accepted_jobs counter
print(x.rejected_jobs)  # Prints out the rejected_jobs counter
print(x.current_difficulty)  # Prints out the current difficulty
```
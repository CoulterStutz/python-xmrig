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
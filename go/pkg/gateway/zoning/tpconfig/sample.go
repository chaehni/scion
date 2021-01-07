package tpconfig

const idSample = "tp"

const tpSample = `
[tp.auth_module]
key = "path"
cert = "path"
key_length = 16
key_ttl = "24h"
key_purge_interval = "24h"
server_port = 9090
max_time_diff = "1s"

[tp.transition_module]
refresh_interval = "5s"
controller_addr = "adress"
`

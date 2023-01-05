# PSP Related tests
This document gives a quick overview of tests associated with PSP. The code is shared as-is, and for demonstration purposes only. It is not ready for netdev@ submission: it does not follow upstream style, nor is it under the proper selftest directory, to list a few.

There may be more tests to come in this directory.

## Prerequisite
The following packages are neede for making pspping binary
```
sudo apt-get install libbpf-dev
sudo apt-get install libcap-dev
```

## To Compile
```
make pspping
```

## Enable PSP and Sanity Check
  * Symbol: INET_PSP
  * Location: -> Networking support (NET [=y]) -> Networking Options -> TCP/IP networking (INET =y)]
  * PSP is on by default if using the kernel source code provided in this directory
```
sysctl -n net.ipv4.psp_enable_conn
```

## Testing
```
# Basic Params
DEV=eth0
SERVER=2002::/64
PORT=8888
```
```
# Standard tests
# Server
./pspping $DEV $PORT
# Client
./pspping $DEV $SERVER $PORT
```
```
Expected logs:
binding to $SERVER port $PORT
Server bound to port $PORT using fd $fd1
Listening
Accepted connection on descriptor $fd2
Got client tuple, client's SPI is $SPI1
binding to $SERVER port $fd3
Secure socket bound to port $p using fd $fd1
Secure socket listening on port $p
My receive SPI is $SPI2
Wrote parameters, got 28 back from write
Awaiting call on secure socket
Accepted connection on descriptor $fd4
Client is sending using SPI $SPI2
Connection closed
user_time=0.001
system_time=0.010
```
```
Extended testing

# Zerobind
./pspping -z $DEV $PORT
./pspping $DEV $SERVER $PORT

# Reuse port
./pspping -s -r1 $DEV $PORT
./pspping $DEV $SERVER $PORT

# Large Send
./pspping $DEV $PORT
./pspping --randomize -S 100000 $DEV $SERVER $PORT

# Fast Open
./pspping $DEV $PORT
./pspping --fastopen $DEV $SERVER $PORT

# With SynCookies
sysctl -w net.ipv4.tcp_syncookies=2 # on server and client
./pspping -v6 $DEV $PORT
./pspping -v6 $DEV $SERVER $PORT

# BPF Program
./pspping -v6 --bpf $DEV $PORT
./pspping -v6 --bpf $DEV $SERVER $PORT
```
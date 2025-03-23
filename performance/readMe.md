# Distributed TLS Performance Testing

This documentation explains how to run TLS 1.3 performance tests with the server and clients on separate machines, allowing for accurate CPU usage monitoring.

## Setup Overview

The testing system consists of two main components:

1. **Server Monitor** (`server_monitor.py`): Runs on the same machine as your chat server and monitors CPU usage
2. **Client Tester** (`client_tester.py`): Runs on a separate machine and generates test load

## Prerequisites

On both machines, install the required Python packages:

```bash
pip install matplotlib numpy psutil
```

## Step 1: Set Up the Server Machine

1. Make sure your chat server is running on your laptop
2. Copy the `server_monitor.py` file to your laptop
3. Create a `results` directory on your laptop if it doesn't exist already
4. Run the server monitor:

```bash
python server_monitor.py
```

This will start the CPU monitoring service on port 8888. Leave this running.

## Step 2: Set Up the Client Machine

1. Copy the `client_tester.py` file to the second laptop
2. Copy your `ChatClient.py` and any required dependencies
3. Create a `results` directory on the client machine if it doesn't exist already
4. Run the client tester, replacing `SERVER_IP` with your server's IP address:

```bash
python client_tester.py SERVER_IP 8080 tls13 100 10 120
```

Arguments:
- `SERVER_IP`: The IP address of your server laptop
- `8080`: The port your chat server is running on
- `tls13`: The TLS version to test (use `tls12` for TLS 1.2)
- `100`: Number of concurrent clients
- `10`: Messages per client
- `120`: Test duration in seconds

## How It Works

1. The client tester connects to the server monitor and sends a "START" command
2. The server monitor begins collecting CPU usage data
3. The client tester creates multiple client connections to your chat server
4. Each client connects, joins a room, and sends messages
5. When the test is complete, the client tester sends a "STOP" command to the server monitor
6. Both the server monitor and client tester generate separate reports

## Understanding the Results

After the test, you'll have results on both machines:

### Server Results (on your laptop)

- `server_cpu_results_TIMESTAMP.txt`: Raw CPU usage data
- `server_cpu_usage_TIMESTAMP.png`: Chart of CPU usage over time

### Client Results (on the second laptop)

- `TLS_1_X_client_results_TIMESTAMP.txt`: Connection and message time statistics
- `TLS_1_X_client_performance_TIMESTAMP.png`: Charts of connection and message times

## Testing TLS 1.2 vs. TLS 1.3

To compare TLS 1.2 and TLS 1.3 performance:

1. Run tests with your TLS 1.3 implementation
2. Update your server to use TLS 1.2
3. Run tests again with the `tls12` parameter
4. Compare the results from both tests

## Troubleshooting

- If the client can't connect to the server monitor, check firewall settings on both machines
- Ensure port 8888 (monitor) and 8080 (chat server) are accessible from the client machine
- If you get connection errors, verify the server IP address is correct and that both machines are on the same network
- Reduce the number of clients if the test is overwhelming either machine
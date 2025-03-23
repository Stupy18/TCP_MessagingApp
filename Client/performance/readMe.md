# TLS Performance Testing Suite

This suite of scripts allows for performance testing and comparison between TLS 1.3 and TLS 1.2 implementations.

## Overview

The testing framework consists of three main components:

1. **performance_test.py**: Tests the server with multiple concurrent clients
2. **compare_results.py**: Compares results from TLS 1.2 and TLS 1.3 tests
3. **run_tests.py**: Manages the testing process

## Prerequisites

Before running the tests, make sure you have the following installed:

```bash
pip install matplotlib numpy psutil
```

## Running the Tests for TLS 1.3 (Current Implementation)

1. Start your server (the current TLS 1.3 implementation)
2. Run the test script:

```bash
python run_tests.py
```

3. Choose option 1 to run the TLS 1.3 test
4. Wait for the test to complete (this may take a few minutes)

## After Implementing TLS 1.2

After you've modified your code to implement TLS 1.2 (in a different branch), you can:

1. Start your server with TLS 1.2 configuration
2. Run the test script again:

```bash
python run_tests.py
```

3. Choose option 2 to run the TLS 1.2 test
4. Wait for the test to complete

## Comparing Results

To compare the results of both tests:

1. Run the comparison script:

```bash
python run_tests.py
```

2. Choose option 3 to compare existing test results
3. Review the output and the generated comparison chart

## Test Configuration

You can adjust the following parameters in `performance_test.py`:

- `NUM_CLIENTS`: Number of concurrent clients (default: 100)
- `MESSAGES_PER_CLIENT`: Number of messages sent by each client (default: 10) 
- `TEST_DURATION`: Duration of the test in seconds (default: 120)
- `SERVER_IP` and `SERVER_PORT`: Server address (default: 127.0.0.1:8080)

## Results Analysis

The test results will be saved in the `results` directory:
- Raw data files: `TLS_1_X_results_TIMESTAMP.txt`
- Performance charts: `TLS_1_X_performance_TIMESTAMP.png`
- Comparison chart: `tls_comparison.png`

## Expected Outcomes

Based on the TLS specifications, you should observe:

1. **TLS 1.3 has faster connection times** due to the reduced handshake (1-RTT vs. 2-RTT)
2. **Lower CPU usage** for TLS 1.3 during connection bursts
3. **Similar message processing times** once connections are established

## Creating the TLS 1.2 Implementation

To create the TLS 1.2 implementation, you'll need to:

1. Create a new branch in your repository
2. Modify the handshake process to follow the TLS 1.2 specification
3. Update the cryptographic methods as needed (e.g., using RSA instead of X25519)
4. Add ChangeCipherSpec messages to the protocol
5. Update the key derivation function to use the TLS 1.2 PRF

## Troubleshooting

If the test hangs or performs poorly:
- Try reducing `NUM_CLIENTS` to reduce system load
- Check server logs for any errors
- Ensure your system has enough resources to handle the test load
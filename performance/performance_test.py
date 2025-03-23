import threading
import time
import sys
import random
import statistics
import os
from datetime import datetime
import matplotlib.pyplot as plt
import sys
import os

import json
import socket
import base64
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Now try the import again
try:
    from Client.ChatClient import ChatClient

    print("Successfully imported ChatClient")
except ImportError as e:
    print(f"Import error: {e}")

    # Try a different approach if the import fails
    try:
        # If we're in the performance folder
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
        from ChatClient import ChatClient

        print("Successfully imported ChatClient using alternate path")
    except ImportError as e:
        print(f"Second import attempt error: {e}")
        sys.exit(1)


# Configuration
SERVER_IP = "127.0.0.1"
SERVER_PORT = 8080
NUM_CLIENTS = 100  # Adjust based on your hardware capability
MESSAGES_PER_CLIENT = 10
MESSAGE_INTERVAL = 0.5  # seconds between messages
TEST_DURATION = 120  # seconds
ROOM_NAMES = ["general", "random", "tech", "news", "games"]
TLS_VERSION = "TLS 1.3"  # Default version

# Results storage
connection_times = []
message_times = []
cpu_samples = []
timestamp_samples = []


def monitor_cpu():
    """Monitor CPU usage during the test"""
    import psutil
    start_time = time.time()

    while time.time() - start_time < TEST_DURATION + 30:  # Run longer than the test
        cpu_percent = psutil.cpu_percent(interval=1)
        timestamp = time.time() - start_time

        cpu_samples.append(cpu_percent)
        timestamp_samples.append(timestamp)

        # Print current CPU usage every 5 seconds
        if int(timestamp) % 5 == 0:
            print(f"CPU Usage at {int(timestamp)}s: {cpu_percent:.1f}%")

        time.sleep(1)


def client_task(client_id):
    """Simulate a client connecting and sending messages"""
    try:
        # Create client
        client = ChatClient()
        username = f"test_user_{client_id}"

        # Connect and record time
        start_time = time.time()
        success, message = client.connect_to_server(SERVER_IP, SERVER_PORT, username)
        connection_time = time.time() - start_time
        connection_times.append(connection_time)

        if not success:
            print(f"Client {client_id} failed to connect: {message}")
            return

        # Join a random room
        room_name = random.choice(ROOM_NAMES)
        client.join_room(room_name)

        # Send messages with random intervals
        for i in range(MESSAGES_PER_CLIENT):
            # Random delay between messages
            time.sleep(random.uniform(0.1, MESSAGE_INTERVAL * 2))

            message = f"Test message {i} from client {client_id} at {time.time()}"

            start_time = time.time()
            success, _ = client.send_message(message)
            if success:
                message_time = time.time() - start_time
                message_times.append(message_time)

        # Wait before disconnecting (some clients stay longer)
        time.sleep(random.uniform(1, 10))
        client.disconnect()

    except Exception as e:
        print(f"Error in client {client_id}: {str(e)}")


def generate_report():
    """Generate and save performance report"""
    if not os.path.exists("results"):
        os.makedirs("results")

    # Calculate statistics
    avg_connection_time = statistics.mean(connection_times) if connection_times else 0
    avg_message_time = statistics.mean(message_times) if message_times else 0
    avg_cpu = statistics.mean(cpu_samples) if cpu_samples else 0
    max_cpu = max(cpu_samples) if cpu_samples else 0

    # Timestamp for the report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    version_str = TLS_VERSION.replace(".", "_")

    # Print results
    print(f"\n--- {TLS_VERSION} Performance Results ---")
    print(f"Number of clients: {NUM_CLIENTS}")
    print(f"Messages per client: {MESSAGES_PER_CLIENT}")
    print(f"Total messages sent: {len(message_times)}")
    print(f"Average connection time: {avg_connection_time:.4f} seconds")
    print(f"Average message sending time: {avg_message_time:.4f} seconds")
    print(f"Average CPU usage: {avg_cpu:.2f}%")
    print(f"Peak CPU usage: {max_cpu:.2f}%")

    # Create charts
    plt.figure(figsize=(15, 10))

    # Connection time histogram
    plt.subplot(2, 2, 1)
    plt.hist(connection_times, bins=20, alpha=0.7, color='blue')
    plt.title(f'{TLS_VERSION} Connection Times')
    plt.xlabel('Seconds')
    plt.ylabel('Frequency')
    plt.grid(True, linestyle='--', alpha=0.7)

    # Message time histogram
    plt.subplot(2, 2, 2)
    plt.hist(message_times, bins=20, alpha=0.7, color='green')
    plt.title(f'{TLS_VERSION} Message Send Times')
    plt.xlabel('Seconds')
    plt.ylabel('Frequency')
    plt.grid(True, linestyle='--', alpha=0.7)

    # CPU usage over time
    plt.subplot(2, 2, 3)
    plt.plot(timestamp_samples, cpu_samples, '-', color='red')
    plt.title(f'{TLS_VERSION} CPU Usage Over Time')
    plt.xlabel('Seconds')
    plt.ylabel('CPU %')
    plt.grid(True, linestyle='--', alpha=0.7)

    # CDF of connection times
    plt.subplot(2, 2, 4)
    sorted_conn_times = sorted(connection_times)
    y_vals = [i / len(sorted_conn_times) for i in range(len(sorted_conn_times))]
    plt.plot(sorted_conn_times, y_vals, '-', color='purple')
    plt.title(f'{TLS_VERSION} Connection Time CDF')
    plt.xlabel('Seconds')
    plt.ylabel('Cumulative Probability')
    plt.grid(True, linestyle='--', alpha=0.7)

    plt.tight_layout()
    plt.savefig(f"results/{version_str}_performance_{timestamp}.png")

    # Save raw data
    with open(f"results/{version_str}_results_{timestamp}.txt", "w") as f:
        f.write(f"Protocol: {TLS_VERSION}\n")
        f.write(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Number of clients: {NUM_CLIENTS}\n")
        f.write(f"Messages per client: {MESSAGES_PER_CLIENT}\n")
        f.write(f"Total messages sent: {len(message_times)}\n")
        f.write(f"Average connection time: {avg_connection_time:.4f} seconds\n")
        f.write(f"Average message sending time: {avg_message_time:.4f} seconds\n")
        f.write(f"Average CPU usage: {avg_cpu:.2f}%\n")
        f.write(f"Peak CPU usage: {max_cpu:.2f}%\n")

        f.write("\nConnection Times:\n")
        for t in connection_times:
            f.write(f"{t:.6f}\n")

        f.write("\nMessage Times:\n")
        for t in message_times:
            f.write(f"{t:.6f}\n")

        f.write("\nCPU Usage:\n")
        for i, c in enumerate(cpu_samples):
            f.write(f"{timestamp_samples[i]:.2f}, {c:.2f}\n")

    print(f"\nResults saved to results/{version_str}_results_{timestamp}.txt")
    print(f"Charts saved to results/{version_str}_performance_{timestamp}.png")


def run_test():
    """Main test function"""
    global TLS_VERSION

    # Check for command-line argument
    if len(sys.argv) > 1:
        if sys.argv[1].lower() == "tls12":
            TLS_VERSION = "TLS 1.2"

    print(f"\nStarting performance test for {TLS_VERSION} with {NUM_CLIENTS} clients...")
    print(f"Server: {SERVER_IP}:{SERVER_PORT}")
    print(f"Test duration: {TEST_DURATION} seconds")
    print(f"Each client will send {MESSAGES_PER_CLIENT} messages")

    # Start CPU monitoring in a separate thread
    try:
        monitor_thread = threading.Thread(target=monitor_cpu)
        monitor_thread.daemon = True
        monitor_thread.start()
        print("CPU monitoring started...")
    except ImportError:
        print("psutil not installed, CPU monitoring disabled")

    # Create and start client threads
    client_threads = []
    start_time = time.time()

    for i in range(NUM_CLIENTS):
        # Stagger client starts to prevent connection flood
        if i > 0 and i % 10 == 0:
            # Print progress every 10 clients
            elapsed = time.time() - start_time
            print(f"Started {i} clients in {elapsed:.2f} seconds...")
            # Wait a bit longer every 10 clients
            time.sleep(1)
        else:
            time.sleep(0.1)

        thread = threading.Thread(target=client_task, args=(i,))
        thread.daemon = True
        thread.start()
        client_threads.append(thread)

    print(f"\nAll {NUM_CLIENTS} clients started. Test in progress...")

    # Wait for test to complete
    test_end_time = time.time() + TEST_DURATION
    while time.time() < test_end_time:
        active = sum(1 for t in client_threads if t.is_alive())
        remaining = int(test_end_time - time.time())
        print(f"Active clients: {active}/{NUM_CLIENTS}. Time remaining: {remaining} seconds...")
        time.sleep(5)

    print("\nTest time completed. Waiting for remaining clients to finish...")

    # Give a grace period for clients to finish
    grace_start = time.time()
    while time.time() - grace_start < 30:  # 30 seconds grace period
        active = sum(1 for t in client_threads if t.is_alive())
        if active == 0:
            break
        print(f"Waiting for {active} clients to finish...")
        time.sleep(5)

    print("\nPerformance test completed.")

    # Generate report
    generate_report()


if __name__ == "__main__":
    run_test()
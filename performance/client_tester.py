import json
import threading
import time
import sys
import random
import statistics
import os
from datetime import datetime
import matplotlib.pyplot as plt
import socket

# Add the parent directory to the path to import ChatClient
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
SERVER_IP = "188.24.92.229"  # Change this to your server's IP address
SERVER_PORT = 8080  # Chat server port
MONITOR_PORT = 8888  # Server monitor communication port
NUM_CLIENTS = 30  # Using fewer clients for more controlled testing
TEST_DURATION = 60  # seconds
ROOM_NAME = "message_test_room"  # All clients will join the same room
TLS_VERSION = "TLS 1.3"  # Default version

# Message size configuration
MESSAGE_SIZES = [10, 100, 500, 1000, 2500, 5000, 7500, 10000, 25000, 50000]  # In bytes/characters
MESSAGES_PER_SIZE = 30  # Number of messages to send for each size

# Results storage
connection_times = []
message_times = {}  # Dictionary to store timing by message size


def send_monitor_command(command):
    """Send command to the server monitor"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, MONITOR_PORT))
        s.send(command.encode('utf-8'))
        response = s.recv(1024).decode('utf-8')
        s.close()
        return response
    except Exception as e:
        print(f"Error communicating with server monitor: {str(e)}")
        return None


def client_task(client_id):
    """Simulate a client connecting and sending messages of varying sizes"""
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

        # Join test room
        client.join_room(ROOM_NAME)

        # Test each message size
        for size in MESSAGE_SIZES:
            # Initialize storage for this size if not already done
            if size not in message_times:
                message_times[size] = []

            # Generate a random message of the specified size
            # Using a mix of letters for more realistic message content
            message_content = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ')
                                      for _ in range(size))

            for i in range(MESSAGES_PER_SIZE // NUM_CLIENTS):
                # Add a small delay between messages to prevent congestion
                time.sleep(random.uniform(0.1, 0.5))

                test_message = f"SIZE:{size}:{message_content}"

                start_time = time.time()
                success, _ = client.send_message(test_message)
                if success:
                    message_time = time.time() - start_time
                    message_times[size].append(message_time)
                    print(f"Client {client_id} sent message of size {size}, time: {message_time:.6f}s")
                else:
                    print(f"Client {client_id} failed to send message of size {size}")

        # Disconnect when done
        client.disconnect()
        print(f"Client {client_id} completed all tests and disconnected")

    except Exception as e:
        print(f"Error in client {client_id}: {str(e)}")


def generate_report():
    """Generate and save performance report for message size testing"""
    if not os.path.exists("results"):
        os.makedirs("results")

    # Calculate statistics
    avg_connection_time = statistics.mean(connection_times) if connection_times else 0

    # Message size statistics
    size_stats = {}
    for size, times in message_times.items():
        if times:
            size_stats[size] = {
                "count": len(times),
                "average": statistics.mean(times),
                "median": statistics.median(times),
                "min": min(times),
                "max": max(times),
                "stdev": statistics.stdev(times) if len(times) > 1 else 0
            }

    # Timestamp for the report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    version_str = TLS_VERSION.replace(".", "_")

    # Print results
    print(f"\n--- {TLS_VERSION} Message Size Performance Results ---")
    print(f"Number of clients: {NUM_CLIENTS}")
    print(f"Average connection time: {avg_connection_time:.4f} seconds")

    for size in sorted(size_stats.keys()):
        stat = size_stats[size]
        print(f"\nMessage size: {size} bytes/chars")
        print(f"  Message count: {stat['count']}")
        print(f"  Average send time: {stat['average']:.6f} seconds")
        print(f"  Median send time: {stat['median']:.6f} seconds")
        print(f"  Min/Max send time: {stat['min']:.6f} / {stat['max']:.6f} seconds")
        print(f"  Standard deviation: {stat['stdev']:.6f} seconds")

    # Create charts - Line chart of average time by message size
    plt.figure(figsize=(12, 8))

    sizes = sorted(size_stats.keys())
    avg_times = [size_stats[size]["average"] for size in sizes]

    plt.plot(sizes, avg_times, 'o-', linewidth=2, markersize=8)
    plt.title(f'{TLS_VERSION} Message Send Times by Size')
    plt.xlabel('Message Size (bytes/chars)')
    plt.ylabel('Average Send Time (seconds)')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.xscale('log')  # Use log scale for better visualization across sizes

    plt.tight_layout()
    plt.savefig(f"results/{version_str}_message_size_performance_{timestamp}.png")

    # Create a second chart - Box plot of time distribution by message size
    plt.figure(figsize=(14, 8))

    # Prepare data for box plot
    box_data = [message_times[size] for size in sorted(message_times.keys())]

    plt.boxplot(box_data, labels=[str(size) for size in sorted(message_times.keys())])
    plt.title(f'{TLS_VERSION} Message Send Time Distribution by Size')
    plt.xlabel('Message Size (bytes/chars)')
    plt.ylabel('Send Time (seconds)')
    plt.grid(True, linestyle='--', alpha=0.7)

    plt.tight_layout()
    plt.savefig(f"results/{version_str}_message_size_boxplot_{timestamp}.png")

    # Save raw data as JSON for easy comparison later
    with open(f"results/{version_str}_message_size_raw_data_{timestamp}.json", "w") as f:
        json.dump({
            "protocol": TLS_VERSION,
            "test_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "connection_stats": {
                "count": len(connection_times),
                "average": avg_connection_time
            },
            "message_stats": size_stats,
            "raw_message_times": {str(k): v for k, v in message_times.items()}
        }, f, indent=2)

    print(f"\nResults saved to results/{version_str}_message_size_raw_data_{timestamp}.json")
    print(f"Charts saved to results/{version_str}_message_size_performance_{timestamp}.png and")
    print(f"results/{version_str}_message_size_boxplot_{timestamp}.png")


def run_test():
    """Main test function for message size testing"""
    global SERVER_IP, SERVER_PORT, NUM_CLIENTS, TLS_VERSION

    # Parse command line arguments
    if len(sys.argv) > 1:
        SERVER_IP = sys.argv[1]

    if len(sys.argv) > 2:
        SERVER_PORT = int(sys.argv[2])

    if len(sys.argv) > 3:
        if sys.argv[3].lower() == "tls12":
            TLS_VERSION = "TLS 1.2"

    if len(sys.argv) > 4:
        NUM_CLIENTS = int(sys.argv[4])

    print(f"\nStarting message size performance test for {TLS_VERSION} with {NUM_CLIENTS} clients...")
    print(f"Server: {SERVER_IP}:{SERVER_PORT}, Monitor: {SERVER_IP}:{MONITOR_PORT}")
    print(f"Testing message sizes: {MESSAGE_SIZES} bytes/chars")
    print(f"Messages per size: {MESSAGES_PER_SIZE}")

    # Tell the server to start monitoring
    print("Signaling server to start monitoring...")
    response = send_monitor_command("START")
    if response != "STARTED":
        print("Warning: Did not receive proper acknowledgment from server monitor")
        if input("Continue anyway? (y/n): ").lower() != 'y':
            return

    # Create and start client threads
    client_threads = []
    start_time = time.time()

    for i in range(NUM_CLIENTS):
        # More sophisticated staggering to prevent connection floods
        stagger_time = 0.5 + (random.random() * 0.5)  # 0.5-1.0 seconds between clients
        time.sleep(stagger_time)

        thread = threading.Thread(target=client_task, args=(i,))
        thread.daemon = True
        thread.start()
        client_threads.append(thread)
        print(f"Started client {i} (stagger: {stagger_time:.2f}s)")

    # Wait for all clients to finish
    for i, thread in enumerate(client_threads):
        thread.join()
        print(f"Client {i} finished")

    # Tell the server to stop monitoring
    print("Signaling server to stop monitoring...")
    response = send_monitor_command("STOP")
    if response != "STOPPED":
        print("Warning: Did not receive proper acknowledgment from server monitor")

    print("\nMessage size performance test completed.")

    # Generate report
    generate_report()


if __name__ == "__main__":
    print("TLS Message Size Performance Tester")
    print("===================================")
    print("This script will test the performance of your TLS chat server")
    print("with messages of different sizes.")
    print()
    print("Usage: python message_size_tester.py [SERVER_IP] [SERVER_PORT] [TLS_VERSION] [NUM_CLIENTS]")
    print("Example: python message_size_tester.py 192.168.1.100 8080 tls13 10")
    print()

    run_test()
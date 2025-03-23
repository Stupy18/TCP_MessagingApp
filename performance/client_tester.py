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
NUM_CLIENTS = 100  # Adjust based on your hardware capability
MESSAGES_PER_CLIENT = 10
MESSAGE_INTERVAL = 0.5  # seconds between messages
TEST_DURATION = 60  # seconds
ROOM_NAMES = ["general", "random", "tech", "news", "games"]
TLS_VERSION = "TLS 1.3"  # Default version

# Results storage
connection_times = []
message_times = []


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


def generate_report():
    """Generate and save performance report"""
    if not os.path.exists("results"):
        os.makedirs("results")

    # Calculate statistics
    avg_connection_time = statistics.mean(connection_times) if connection_times else 0
    avg_message_time = statistics.mean(message_times) if message_times else 0

    # Timestamp for the report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    version_str = TLS_VERSION.replace(".", "_")

    # Print results
    print(f"\n--- {TLS_VERSION} Client Performance Results ---")
    print(f"Number of clients: {NUM_CLIENTS}")
    print(f"Messages per client: {MESSAGES_PER_CLIENT}")
    print(f"Total messages sent: {len(message_times)}")
    print(f"Average connection time: {avg_connection_time:.4f} seconds")
    print(f"Average message sending time: {avg_message_time:.4f} seconds")

    # Create charts
    plt.figure(figsize=(15, 10))

    # Connection time histogram
    plt.subplot(2, 1, 1)
    plt.hist(connection_times, bins=20, alpha=0.7, color='blue')
    plt.title(f'{TLS_VERSION} Connection Times')
    plt.xlabel('Seconds')
    plt.ylabel('Frequency')
    plt.grid(True, linestyle='--', alpha=0.7)

    # Message time histogram
    plt.subplot(2, 1, 2)
    plt.hist(message_times, bins=20, alpha=0.7, color='green')
    plt.title(f'{TLS_VERSION} Message Send Times')
    plt.xlabel('Seconds')
    plt.ylabel('Frequency')
    plt.grid(True, linestyle='--', alpha=0.7)

    plt.tight_layout()
    plt.savefig(f"results/{version_str}_client_performance_{timestamp}.png")

    # Save raw data
    with open(f"results/{version_str}_client_results_{timestamp}.txt", "w") as f:
        f.write(f"Protocol: {TLS_VERSION}\n")
        f.write(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Number of clients: {NUM_CLIENTS}\n")
        f.write(f"Messages per client: {MESSAGES_PER_CLIENT}\n")
        f.write(f"Total messages sent: {len(message_times)}\n")
        f.write(f"Average connection time: {avg_connection_time:.4f} seconds\n")
        f.write(f"Average message sending time: {avg_message_time:.4f} seconds\n")

        f.write("\nConnection Times:\n")
        for t in connection_times:
            f.write(f"{t:.6f}\n")

        f.write("\nMessage Times:\n")
        for t in message_times:
            f.write(f"{t:.6f}\n")

    print(f"\nResults saved to results/{version_str}_client_results_{timestamp}.txt")
    print(f"Charts saved to results/{version_str}_client_performance_{timestamp}.png")


def run_test():
    """Main test function"""
    global SERVER_IP, SERVER_PORT, NUM_CLIENTS, MESSAGES_PER_CLIENT, TEST_DURATION, TLS_VERSION

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

    if len(sys.argv) > 5:
        MESSAGES_PER_CLIENT = int(sys.argv[5])

    if len(sys.argv) > 6:
        TEST_DURATION = int(sys.argv[6])

    print(f"\nStarting performance test for {TLS_VERSION} with {NUM_CLIENTS} clients...")
    print(f"Server: {SERVER_IP}:{SERVER_PORT}, Monitor: {SERVER_IP}:{MONITOR_PORT}")
    print(f"Test duration: {TEST_DURATION} seconds")
    print(f"Each client will send {MESSAGES_PER_CLIENT} messages")

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

    # Tell the server to stop monitoring
    print("Signaling server to stop monitoring...")
    response = send_monitor_command("STOP")
    if response != "STOPPED":
        print("Warning: Did not receive proper acknowledgment from server monitor")

    print("\nPerformance test completed.")

    # Generate client-side report
    generate_report()


if __name__ == "__main__":
    print("TLS Client Performance Tester")
    print("=============================")
    print("This script will test the performance of your TLS chat server")
    print("from the client perspective.")
    print()
    print(
        "Usage: python client_tester.py [SERVER_IP] [SERVER_PORT] [TLS_VERSION] [NUM_CLIENTS] [MSGS_PER_CLIENT] [DURATION]")
    print("Example: python client_tester.py 192.168.1.100 8080 tls13 100 10 120")
    print()

    run_test()
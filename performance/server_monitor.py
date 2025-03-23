import time
import sys
import os
import psutil
import matplotlib.pyplot as plt
from datetime import datetime
import threading
import socket

# Configuration
SERVER_PORT = 8888  # Port for the monitoring communication
TEST_DURATION = 120  # seconds
MONITOR_INTERVAL = 1  # seconds

# Results storage
cpu_samples = []
timestamp_samples = []
server_ready = False
test_running = False
test_complete = False


def monitor_cpu():
    """Monitor CPU usage during the test"""
    global cpu_samples, timestamp_samples, test_running, test_complete

    print("Starting CPU monitoring...")
    start_time = time.time()

    while not test_complete:
        if test_running:
            cpu_percent = psutil.cpu_percent(interval=MONITOR_INTERVAL)
            timestamp = time.time() - start_time

            cpu_samples.append(cpu_percent)
            timestamp_samples.append(timestamp)

            # Print current CPU usage every 5 seconds
            if int(timestamp) % 5 == 0:
                print(f"CPU Usage at {int(timestamp)}s: {cpu_percent:.1f}%")

    print("CPU monitoring stopped.")


def start_monitor_server():
    """Start a simple TCP server to receive commands from the client tester"""
    global server_ready, test_running, test_complete

    monitor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    monitor_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        monitor_socket.bind(('0.0.0.0', SERVER_PORT))
        monitor_socket.listen(1)
        print(f"Monitoring server listening on port {SERVER_PORT}")
        server_ready = True

        while not test_complete:
            conn, addr = monitor_socket.accept()
            print(f"Connection from {addr}")

            data = conn.recv(1024).decode('utf-8')
            if data == "START":
                print("Received START command. Beginning test monitoring...")
                test_running = True
                conn.send("STARTED".encode('utf-8'))
            elif data == "STOP":
                print("Received STOP command. Stopping test monitoring...")
                test_running = False
                test_complete = True
                generate_report()
                conn.send("STOPPED".encode('utf-8'))

            conn.close()

    except Exception as e:
        print(f"Error in monitor server: {str(e)}")
    finally:
        monitor_socket.close()


def generate_report():
    """Generate and save performance report"""
    if not os.path.exists("results"):
        os.makedirs("results")

    # Calculate statistics
    if cpu_samples:
        avg_cpu = sum(cpu_samples) / len(cpu_samples)
        max_cpu = max(cpu_samples)
    else:
        avg_cpu = 0
        max_cpu = 0

    # Timestamp for the report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Print results
    print("\n--- Server CPU Performance Results ---")
    print(f"Test duration: approximately {len(cpu_samples)} seconds")
    print(f"Average CPU usage: {avg_cpu:.2f}%")
    print(f"Peak CPU usage: {max_cpu:.2f}%")

    # Create charts
    plt.figure(figsize=(12, 6))

    # CPU usage over time
    plt.plot(timestamp_samples, cpu_samples, '-', color='red')
    plt.title('Server CPU Usage Over Time')
    plt.xlabel('Seconds')
    plt.ylabel('CPU %')
    plt.grid(True, linestyle='--', alpha=0.7)

    plt.tight_layout()
    plt.savefig(f"results/server_cpu_usage_{timestamp}.png")

    # Save raw data
    with open(f"results/server_cpu_results_{timestamp}.txt", "w") as f:
        f.write(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Test duration: approximately {len(cpu_samples)} seconds\n")
        f.write(f"Average CPU usage: {avg_cpu:.2f}%\n")
        f.write(f"Peak CPU usage: {max_cpu:.2f}%\n")

        f.write("\nCPU Usage:\n")
        for i, c in enumerate(cpu_samples):
            f.write(f"{timestamp_samples[i]:.2f}, {c:.2f}\n")

    print(f"\nResults saved to results/server_cpu_results_{timestamp}.txt")
    print(f"Chart saved to results/server_cpu_usage_{timestamp}.png")


def main():
    # Start CPU monitoring in a separate thread
    monitor_thread = threading.Thread(target=monitor_cpu)
    monitor_thread.daemon = True
    monitor_thread.start()

    # Start the monitor server in the main thread
    start_monitor_server()


if __name__ == "__main__":
    print("Server CPU Monitor")
    print("=================")
    print("This script will monitor the server's CPU usage during performance testing.")
    print("Make sure your chat server is already running.")
    print("The client test script should be run on a separate machine.")

    main()
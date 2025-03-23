import os
import sys
import time
import subprocess
import threading
import signal
import platform


def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if platform.system() == 'Windows' else 'clear')


def start_server():
    """Start the server in a separate process"""
    print("Starting server...")

    if platform.system() == 'Windows':
        # Use pythonw to avoid console window on Windows
        server_process = subprocess.Popen(['pythonw', 'Server_Gui.py'])
    else:
        server_process = subprocess.Popen(['python', 'Server_Gui.py'])

    # Give the server some time to start
    time.sleep(5)
    return server_process


def run_performance_test(tls_version="tls13"):
    """Run performance test with specified TLS version"""
    clear_screen()
    print(f"Running performance test for {'TLS 1.3' if tls_version == 'tls13' else 'TLS 1.2'}...")

    # Use the same Python executable that's running this script
    python_executable = sys.executable

    # Get the absolute path to the performance_test.py script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    performance_script = os.path.join(script_dir, 'performance_test.py')

    # Build the command with the full path to both Python and the script
    args = [python_executable, performance_script]
    if tls_version == "tls12":
        args.append('tls12')

    # Use subprocess to run the script in the same environment
    process_env = os.environ.copy()
    process_env['PYTHONPATH'] = os.path.dirname(script_dir) + os.pathsep + process_env.get('PYTHONPATH', '')

    subprocess.run(args, env=process_env)


def main():
    # Create results directory if it doesn't exist
    if not os.path.exists('results'):
        os.makedirs('results')

    print("TLS Performance Testing Script")
    print("=============================")
    print("This script will run performance tests for both TLS 1.3 and TLS 1.2.")
    print("Make sure your server is configured correctly for each test.")
    print("\nOptions:")
    print("1. Run TLS 1.3 test only")
    print("2. Run TLS 1.2 test only (after you've modified your code)")
    print("3. Compare existing test results")
    print("4. Run both tests (requires server restart between tests)")
    print("5. Exit")

    choice = input("\nEnter your choice (1-5): ")

    if choice == "1":
        # TLS 1.3 test only
        print("\nStarting TLS 1.3 test...")
        print("Make sure your server is running with TLS 1.3 configuration.")
        input("Press Enter when server is ready...")

        run_performance_test("tls13")

    elif choice == "2":
        # TLS 1.2 test only
        print("\nStarting TLS 1.2 test...")
        print("Make sure your server is running with TLS 1.2 configuration.")
        input("Press Enter when server is ready...")

        run_performance_test("tls12")

    elif choice == "3":
        # Compare existing results
        subprocess.run(['python', 'compare_results.py'])

    elif choice == "4":
        # Run both tests
        print("\nThis will run both TLS 1.3 and TLS 1.2 tests.")
        print("You'll need to restart your server between tests.")

        # TLS 1.3 test
        print("\nFirst, make sure your server is running with TLS 1.3 configuration.")
        input("Press Enter when server is ready...")
        run_performance_test("tls13")

        # TLS 1.2 test
        print("\nNow, please restart your server with TLS 1.2 configuration.")
        input("Press Enter when TLS 1.2 server is ready...")
        run_performance_test("tls12")

        # Compare results
        print("\nComparing results...")
        subprocess.run(['python', 'compare_results.py'])

    elif choice == "5":
        # Exit
        print("Exiting...")
        sys.exit(0)

    else:
        print("Invalid choice. Please run the script again.")


if __name__ == "__main__":
    main()
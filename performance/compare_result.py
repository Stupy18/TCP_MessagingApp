import os
import glob
import re
import matplotlib.pyplot as plt
import numpy as np


def parse_results_file(filename):
    """Extract metrics from a results file"""
    metrics = {}
    with open(filename, 'r') as f:
        lines = f.readlines()

    # Extract metrics from header
    for line in lines[:20]:  # Check first 20 lines for metrics
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            try:
                # Try to convert to number if possible
                value = float(value.strip().split()[0])
                metrics[key] = value
            except (ValueError, IndexError):
                # Otherwise keep as string
                metrics[key] = value.strip()

    # Extract CPU usage data
    cpu_data = []
    timestamps = []

    cpu_section = False
    for line in lines:
        if line.strip() == "CPU Usage:":
            cpu_section = True
            continue

        if cpu_section and "," in line:
            try:
                timestamp, cpu = line.strip().split(',')
                timestamps.append(float(timestamp))
                cpu_data.append(float(cpu))
            except (ValueError, IndexError):
                pass

    return metrics, timestamps, cpu_data


def find_latest_results():
    """Find the latest TLS 1.2 and TLS 1.3 result files"""
    tls12_files = glob.glob('results/TLS_1_2_results_*.txt')
    tls13_files = glob.glob('results/TLS_1_3_results_*.txt')

    if not tls12_files or not tls13_files:
        print("Could not find both TLS 1.2 and TLS 1.3 result files.")
        print("Please run the performance tests for both versions first.")
        return None, None

    # Sort by timestamp in filename (assuming format *_YYYYMMDD_HHMMSS.txt)
    tls12_files.sort(key=lambda x: re.search(r'(\d{8}_\d{6})', x).group(1), reverse=True)
    tls13_files.sort(key=lambda x: re.search(r'(\d{8}_\d{6})', x).group(1), reverse=True)

    return tls12_files[0], tls13_files[0]


def generate_comparison_chart(tls12_file, tls13_file):
    """Generate charts comparing TLS 1.2 and TLS 1.3 performance"""
    tls12_metrics, tls12_timestamps, tls12_cpu = parse_results_file(tls12_file)
    tls13_metrics, tls13_timestamps, tls13_cpu = parse_results_file(tls13_file)

    print("\n=== Performance Comparison: TLS 1.2 vs TLS 1.3 ===")
    print(f"TLS 1.2 file: {tls12_file}")
    print(f"TLS 1.3 file: {tls13_file}")

    # Create comparison metrics
    metrics_to_compare = [
        "Average connection time",
        "Average message sending time",
        "Average CPU usage",
        "Peak CPU usage"
    ]

    # Create a table for comparison
    print("\nMetric               TLS 1.2      TLS 1.3      Difference    % Change")
    print("-------------------------------------------------------------------------")

    for metric in metrics_to_compare:
        if metric in tls12_metrics and metric in tls13_metrics:
            tls12_val = tls12_metrics[metric]
            tls13_val = tls13_metrics[metric]
            diff = tls13_val - tls12_val
            pct_change = (diff / tls12_val) * 100 if tls12_val != 0 else 0

            direction = "faster" if "time" in metric.lower() and diff < 0 else "slower"
            if "cpu" in metric.lower():
                direction = "less" if diff < 0 else "more"

            print(f"{metric:<20} {tls12_val:<12.4f} {tls13_val:<12.4f} {diff:<12.4f} {pct_change:>6.2f}% ({direction})")

    # Create comparison charts
    plt.figure(figsize=(15, 10))

    # Bar chart of key metrics
    plt.subplot(2, 2, 1)
    labels = ["Conn Time (s)", "Msg Time (s)", "Avg CPU (%)", "Peak CPU (%)"]
    tls12_values = [
        tls12_metrics.get("Average connection time", 0),
        tls12_metrics.get("Average message sending time", 0),
        tls12_metrics.get("Average CPU usage", 0),
        tls12_metrics.get("Peak CPU usage", 0)
    ]
    tls13_values = [
        tls13_metrics.get("Average connection time", 0),
        tls13_metrics.get("Average message sending time", 0),
        tls13_metrics.get("Average CPU usage", 0),
        tls13_metrics.get("Peak CPU usage", 0)
    ]

    x = np.arange(len(labels))
    width = 0.35

    plt.bar(x - width / 2, tls12_values, width, label='TLS 1.2', color='#3274A1')
    plt.bar(x + width / 2, tls13_values, width, label='TLS 1.3', color='#E1812C')

    plt.ylabel('Value')
    plt.title('TLS 1.2 vs TLS 1.3 Performance Metrics')
    plt.xticks(x, labels)
    plt.legend()

    # Add percentage labels
    for i in range(len(labels)):
        if tls12_values[i] > 0:
            pct_change = ((tls13_values[i] - tls12_values[i]) / tls12_values[i]) * 100
            y_pos = max(tls12_values[i], tls13_values[i]) * 1.05
            label = f"{pct_change:.1f}%"
            plt.annotate(label, xy=(i, y_pos), ha='center', fontweight='bold')

    # CPU usage over time
    plt.subplot(2, 2, 2)
    if tls12_timestamps and tls13_timestamps:
        plt.plot(tls12_timestamps, tls12_cpu, 'b-', label='TLS 1.2', alpha=0.7)
        plt.plot(tls13_timestamps, tls13_cpu, 'r-', label='TLS 1.3', alpha=0.7)
        plt.title('CPU Usage Over Time')
        plt.xlabel('Time (seconds)')
        plt.ylabel('CPU %')
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.legend()

    # Connection time comparison
    plt.subplot(2, 2, 3)
    conn_time_tls12 = tls12_metrics.get("Average connection time", 0)
    conn_time_tls13 = tls13_metrics.get("Average connection time", 0)
    plt.bar(['TLS 1.2', 'TLS 1.3'], [conn_time_tls12, conn_time_tls13], color=['#3274A1', '#E1812C'])
    plt.title('Average Connection Time (seconds)')
    plt.ylabel('Seconds')
    plt.grid(True, linestyle='--', alpha=0.7, axis='y')

    # Add specific improvement percentage
    if conn_time_tls12 > 0:
        pct_change = ((conn_time_tls13 - conn_time_tls12) / conn_time_tls12) * 100
        label = f"{pct_change:.1f}% {'faster' if pct_change < 0 else 'slower'}"
        plt.annotate(label, xy=(1, conn_time_tls13 * 1.05), ha='center', fontweight='bold')

    # Message time comparison
    plt.subplot(2, 2, 4)
    msg_time_tls12 = tls12_metrics.get("Average message sending time", 0)
    msg_time_tls13 = tls13_metrics.get("Average message sending time", 0)
    plt.bar(['TLS 1.2', 'TLS 1.3'], [msg_time_tls12, msg_time_tls13], color=['#3274A1', '#E1812C'])
    plt.title('Average Message Sending Time (seconds)')
    plt.ylabel('Seconds')
    plt.grid(True, linestyle='--', alpha=0.7, axis='y')

    # Add specific improvement percentage
    if msg_time_tls12 > 0:
        pct_change = ((msg_time_tls13 - msg_time_tls12) / msg_time_tls12) * 100
        label = f"{pct_change:.1f}% {'faster' if pct_change < 0 else 'slower'}"
        plt.annotate(label, xy=(1, msg_time_tls13 * 1.05), ha='center', fontweight='bold')

    plt.tight_layout()

    # Save comparison chart
    comparison_file = 'results/tls_comparison.png'
    plt.savefig(comparison_file)
    print(f"\nComparison chart saved to {comparison_file}")


def main():
    if not os.path.exists('results'):
        print("Error: 'results' directory not found. Please run the performance tests first.")
        return

    tls12_file, tls13_file = find_latest_results()

    if tls12_file and tls13_file:
        generate_comparison_chart(tls12_file, tls13_file)
    else:
        print("Could not generate comparison. Make sure to run tests for both TLS versions.")


if __name__ == "__main__":
    main()
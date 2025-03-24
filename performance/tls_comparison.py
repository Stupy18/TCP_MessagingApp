import json
import os
import sys
import glob
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime


def load_latest_results(version_str):
    """Load the most recent test results for the specified TLS version"""
    # Find latest result file
    pattern = f"results/{version_str}_message_size_raw_data_*.json"
    files = glob.glob(pattern)

    if not files:
        print(f"No result files found for {version_str.replace('_', '.')}!")
        return None

    # Sort by timestamp (which is in the filename)
    latest_file = sorted(files)[-1]

    # Load and return the data
    with open(latest_file, 'r') as f:
        return json.load(f)


def create_comparison(tls12_data, tls13_data):
    """Create comparison charts and report between TLS 1.2 and TLS 1.3 results"""
    if not os.path.exists("results"):
        os.makedirs("results")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Calculate performance improvements
    improvements = {}

    # Get the common message sizes
    tls12_sizes = [int(k) for k in tls12_data["message_stats"].keys()]
    tls13_sizes = [int(k) for k in tls13_data["message_stats"].keys()]
    common_sizes = sorted(set(tls12_sizes) & set(tls13_sizes))

    for size in common_sizes:
        size_str = str(size)
        tls12_avg = tls12_data["message_stats"][size_str]["average"]
        tls13_avg = tls13_data["message_stats"][size_str]["average"]

        # Calculate percentage improvement (negative means TLS 1.3 is faster)
        improvement_pct = ((tls13_avg - tls12_avg) / tls12_avg) * 100
        improvements[size] = {
            "tls12_avg": tls12_avg,
            "tls13_avg": tls13_avg,
            "improvement_pct": improvement_pct
        }

    # Chart 1: Comparison of average send times
    plt.figure(figsize=(14, 8))

    sizes = sorted(common_sizes)
    tls12_avgs = [tls12_data["message_stats"][str(size)]["average"] for size in sizes]
    tls13_avgs = [tls13_data["message_stats"][str(size)]["average"] for size in sizes]

    plt.plot(sizes, tls12_avgs, 'o-', color='blue', linewidth=2, label='TLS 1.2', markersize=8)
    plt.plot(sizes, tls13_avgs, 's-', color='red', linewidth=2, label='TLS 1.3', markersize=8)

    plt.title('TLS 1.2 vs TLS 1.3: Message Send Times by Size')
    plt.xlabel('Message Size (bytes)')
    plt.ylabel('Average Send Time (seconds)')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend()
    plt.xscale('log')

    plt.tight_layout()
    plt.savefig(f"results/tls_version_comparison_{timestamp}.png")

    # Chart 2: Percentage improvement
    plt.figure(figsize=(14, 8))

    improvement_pcts = [improvements[size]["improvement_pct"] for size in sizes]

    # Create a bar chart
    bars = plt.bar(
        np.arange(len(sizes)),
        improvement_pcts,
        color=['green' if pct < 0 else 'red' for pct in improvement_pcts]
    )

    # Add labels
    plt.axhline(y=0, color='black', linestyle='-', alpha=0.3)
    plt.title('TLS 1.3 Performance Change vs TLS 1.2 (%)')
    plt.xlabel('Message Size (bytes)')
    plt.ylabel('Performance Change (%)\nNegative = TLS 1.3 Faster')
    plt.xticks(np.arange(len(sizes)), [str(size) for size in sizes])
    plt.grid(True, axis='y', linestyle='--', alpha=0.7)

    # Add value labels on the bars
    for i, bar in enumerate(bars):
        height = bar.get_height()
        label_y_pos = height + 1 if height > 0 else height - 3
        plt.text(bar.get_x() + bar.get_width() / 2, label_y_pos,
                 f'{improvement_pcts[i]:.1f}%', ha='center', va='bottom' if height > 0 else 'top')

    plt.tight_layout()
    plt.savefig(f"results/tls_performance_improvement_{timestamp}.png")

    # Generate a detailed comparison report
    with open(f"results/tls_comparison_report_{timestamp}.txt", "w") as f:
        f.write("TLS 1.2 vs TLS 1.3 Performance Comparison\n")
        f.write("==========================================\n\n")

        f.write(f"Comparison generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("Connection Performance:\n")
        f.write("----------------------\n")
        tls12_conn = tls12_data["connection_stats"]["average"]
        tls13_conn = tls13_data["connection_stats"]["average"]
        conn_pct = ((tls13_conn - tls12_conn) / tls12_conn) * 100

        f.write(f"TLS 1.2 average connection time: {tls12_conn:.6f} seconds\n")
        f.write(f"TLS 1.3 average connection time: {tls13_conn:.6f} seconds\n")
        f.write(f"Connection time change: {conn_pct:.2f}% ({'faster' if conn_pct < 0 else 'slower'})\n\n")

        f.write("Message Sending Performance by Size:\n")
        f.write("---------------------------------\n")

        for size in sizes:
            f.write(f"\nMessage size: {size} bytes\n")
            imp = improvements[size]
            f.write(f"  TLS 1.2 average send time: {imp['tls12_avg']:.6f} seconds\n")
            f.write(f"  TLS 1.3 average send time: {imp['tls13_avg']:.6f} seconds\n")
            f.write(
                f"  Performance change: {imp['improvement_pct']:.2f}% ({'faster' if imp['improvement_pct'] < 0 else 'slower'})\n")

        # Overall assessment
        f.write("\n\nOverall Assessment:\n")
        f.write("-----------------\n")

        avg_improvement = sum(imp["improvement_pct"] for imp in improvements.values()) / len(improvements)

        if avg_improvement < 0:
            f.write(f"TLS 1.3 is on average {-avg_improvement:.2f}% faster than TLS 1.2 for message transmission.\n")
        else:
            f.write(f"TLS 1.3 is on average {avg_improvement:.2f}% slower than TLS 1.2 for message transmission.\n")

        # Additional observations
        f.write("\nAdditional Observations:\n")
        if conn_pct < 0:
            f.write(f"- TLS 1.3 establishes connections {-conn_pct:.2f}% faster than TLS 1.2.\n")
        else:
            f.write(f"- TLS 1.3 establishes connections {conn_pct:.2f}% slower than TLS 1.2.\n")

        # Message size observations
        size_effects = []
        for size in sizes:
            if improvements[size]["improvement_pct"] < -5:  # 5% faster
                size_effects.append(
                    f"TLS 1.3 is significantly faster for {size}-byte messages ({-improvements[size]['improvement_pct']:.1f}% improvement)")
            elif improvements[size]["improvement_pct"] > 5:  # 5% slower
                size_effects.append(
                    f"TLS 1.3 is slower for {size}-byte messages ({improvements[size]['improvement_pct']:.1f}% slower)")

        for observation in size_effects:
            f.write(f"- {observation}.\n")

        # Technical reasons
        f.write("\nPossible Technical Reasons for Performance Differences:\n")
        f.write("- TLS 1.3 reduces the handshake from 2-RTT to 1-RTT, which should improve connection establishment.\n")
        f.write(
            "- TLS 1.3 introduces more efficient cipher suites, potentially improving encryption/decryption speed.\n")
        f.write("- TLS 1.3 removes legacy algorithms and options, which may lead to simpler and faster code paths.\n")

        # Recommendations
        f.write("\nRecommendations:\n")
        if avg_improvement < 0:
            f.write("- Based on performance metrics, TLS 1.3 is recommended over TLS 1.2 for this application.\n")
        else:
            f.write("- Despite newer design, TLS 1.3 does not show performance improvements in this implementation.\n")
            f.write("  Further optimizations may be necessary to realize expected benefits.\n")

    print(f"\nResults saved to:")
    print(f"- results/tls_version_comparison_{timestamp}.png")
    print(f"- results/tls_performance_improvement_{timestamp}.png")
    print(f"- results/tls_comparison_report_{timestamp}.txt")

    return timestamp


def main():
    # Load latest results for each version
    print("Loading latest TLS 1.2 results...")
    tls12_data = load_latest_results("TLS_1_2")

    print("Loading latest TLS 1.3 results...")
    tls13_data = load_latest_results("TLS_1_3")

    if not tls12_data or not tls13_data:
        print("Error: Missing results for one or both TLS versions.")
        print("Please run the message_size_tester.py script for both TLS 1.2 and TLS 1.3 first.")
        return

    print("Creating comparison charts and report...")
    create_comparison(tls12_data, tls13_data)

    print("\nComparison completed successfully!")


if __name__ == "__main__":
    print("TLS 1.2 vs TLS 1.3 Performance Comparison Tool")
    print("=============================================")
    print("This script compares performance results from TLS 1.2 and TLS 1.3 tests")
    print("to provide a comprehensive analysis for your thesis.")
    print()

    main()
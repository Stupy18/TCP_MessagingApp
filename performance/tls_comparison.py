import json
import os
import sys
import glob
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime


def load_results(version_str, filename):
    """Load the specified TLS version results file"""
    # Construct the filepath based on the screenshot
    filepath = os.path.join("results", filename)

    # Check if file exists
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        # Try alternative path
        filepath = filename
        if not os.path.exists(filepath):
            print(f"Also not found at: {filepath}")
            # Try with full path
            filepath = os.path.join("performance", "results", filename)
            if not os.path.exists(filepath):
                print(f"Also not found at: {filepath}")
                return None

    print(f"Loading file: {filepath}")
    # Load and return the data
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading file: {str(e)}")
        return None


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

    plt.plot(sizes, tls12_avgs, 'o-', color='blue', linewidth=2, label='TLS 1.2 (CBC)', markersize=8)
    plt.plot(sizes, tls13_avgs, 's-', color='red', linewidth=2, label='TLS 1.3 (GCM)', markersize=8)

    plt.title('TLS 1.2 (CBC) vs TLS 1.3 (GCM): Message Send Times by Size')
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
    plt.title('TLS 1.3 (GCM) Performance Change vs TLS 1.2 (CBC) (%)')
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
        f.write("TLS 1.2 (CBC) vs TLS 1.3 (GCM) Performance Comparison\n")
        f.write("==================================================\n\n")

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
            f.write(
                f"TLS 1.3 with GCM is on average {-avg_improvement:.2f}% faster than TLS 1.2 with CBC for message transmission.\n")
        else:
            f.write(
                f"TLS 1.3 with GCM is on average {avg_improvement:.2f}% slower than TLS 1.2 with CBC for message transmission.\n")

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
        f.write("\nTechnical Reasons for Performance Differences:\n")
        f.write("- TLS 1.3 reduces the handshake from 2-RTT to 1-RTT, improving connection establishment time.\n")
        f.write(
            "- CBC mode (TLS 1.2) processes blocks sequentially, while GCM mode (TLS 1.3) can process multiple blocks in parallel.\n")
        f.write("- CBC mode requires explicit PKCS7 padding which adds computational overhead.\n")
        f.write(
            "- CBC with HMAC requires two passes over the data (encryption + authentication) compared to GCM's single pass.\n")
        f.write(
            "- Modern CPUs have specific hardware instructions (AES-NI and PCLMULQDQ) that accelerate GCM operations.\n")
        f.write("- TLS 1.3 removes legacy algorithms and options, which leads to simpler and faster code paths.\n")

        # Recommendations
        f.write("\nRecommendations:\n")
        if avg_improvement < 0:
            f.write(
                "- Based on performance metrics, TLS 1.3 with GCM is recommended over TLS 1.2 with CBC for this application.\n")
            f.write(
                "- The performance improvement is especially significant for applications handling larger message sizes.\n")
        else:
            f.write(
                "- Despite theoretical advantages, TLS 1.3 with GCM does not show performance improvements in this implementation.\n")
            f.write("- Further optimization of the GCM implementation may be necessary to realize expected benefits.\n")

    print(f"\nResults saved to:")
    print(f"- results/tls_version_comparison_{timestamp}.png")
    print(f"- results/tls_performance_improvement_{timestamp}.png")
    print(f"- results/tls_comparison_report_{timestamp}.txt")

    return timestamp


def main():
    # Get current directory and print it
    current_dir = os.getcwd()
    print(f"Current working directory: {current_dir}")

    # Print available files in the results directory
    results_dir = os.path.join("results")
    print(f"Looking for files in: {results_dir}")
    if os.path.exists(results_dir):
        print("Files in results directory:")
        for file in os.listdir(results_dir):
            print(f"  {file}")
    else:
        print("Results directory not found!")

    # Hardcoded filenames based on the screenshot provided
    tls12_filename = "TLS 1_2_message_size_raw_data_20250331_172059.json"
    tls13_filename = "TLS 1_3_message_size_raw_data_20250331_171315.json"

    print("\nLoading TLS 1.2 results...")
    tls12_data = load_results("1.2", tls12_filename)

    print("Loading TLS 1.3 results...")
    tls13_data = load_results("1.3", tls13_filename)

    if not tls12_data or not tls13_data:
        print("Error: Missing results for one or both TLS versions.")
        print("Please check file paths and ensure the JSON files exist.")
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
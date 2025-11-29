# Network Intrusion Detection System (NIDS) Project

This project demonstrates a Network Intrusion Detection System. It includes configuration files for **Snort** (a standard industry tool) and a custom **Python-based NIDS** using Scapy for educational and demonstration purposes.

## Project Structure

- `snort_config/`: Contains configuration files for Snort.
  - `snort.conf`: A minimal Snort configuration file.
  - `local.rules`: Custom rules to detect specific network traffic (ICMP, SSH, etc.).
- `python_nids/`: A Python implementation of a simple NIDS.
  - `nids.py`: The main script that sniffs traffic and matches it against rules.
  - `requirements.txt`: Python dependencies.
- `visualization/`: Tools to visualize the logs.
  - `dashboard.py`: Generates charts from the logs created by `nids.py`.

## User Guide

### Option 1: Using the Python NIDS (Recommended for Quick Start)

This option allows you to run a NIDS immediately without installing complex binary tools.

#### Prerequisites
1.  Install [Npcap](https://npcap.com/) (Required for Scapy on Windows). **Important:** During installation, check "Install Npcap in WinPcap API-compatible Mode".
2.  Install Python dependencies:
    ```bash
    pip install -r python_nids/requirements.txt
    ```

#### Running the NIDS
1.  Open a terminal as **Administrator** (required for sniffing).
2.  Navigate to the `python_nids` directory:
    ```bash
    cd python_nids
    ```
3.  Run the NIDS script:
    ```bash
    python nids.py
    ```
4.  Generate some traffic (e.g., ping your machine, open a browser). You should see alerts in the console.

#### Visualizing Attacks
1.  After running the NIDS for a while, stop it (Ctrl+C).
2.  Run the dashboard script:
    ```bash
    cd ../visualization
    python dashboard.py
    ```

### Option 2: Using Snort (Advanced)

If you have Snort installed on your system:

1.  Copy the files from `snort_config/` to your Snort configuration directory (usually `C:\Snort\etc` on Windows or `/etc/snort` on Linux).
2.  Run Snort using the provided configuration:
    ```bash
    snort -i <interface_index> -c snort_config/snort.conf -A console
    ```
    (Replace `<interface_index>` with your network interface number, found using `snort -W`).

## Features Implemented

1.  **Traffic Monitoring**: Continuous monitoring of network packets using Scapy.
2.  **Rule-Based Detection**: Detects ICMP (Ping), SSH, FTP, HTTP, and HTTPS traffic based on defined rules.
3.  **Alerting**: Logs alerts to a JSON file and prints them to the console.
4.  **Response Mechanism**: Automatically simulates blocking the source IP of detected threats (e.g., firewall block simulation).
5.  **Visualization**: Bar charts and pie charts showing the distribution of detected threats.

## Task Completion Status (Task 4)

| Requirement | Status | Implementation Details |
| :--- | :--- | :--- |
| **1. Set up NIDS** | ✅ Completed | Implemented using Python/Scapy (custom NIDS) and Snort configurations provided. |
| **2. Configure Rules** | ✅ Completed | Rules configured for ICMP, HTTP, HTTPS, SSH, and FTP. |
| **3. Monitor Traffic** | ✅ Completed | `nids.py` runs a continuous packet sniffer loop. |
| **4. Response Mechanisms** | ✅ Completed | `take_response_action()` function simulates blocking malicious IPs. |
| **5. Visualize Attacks** | ✅ Completed | `dashboard.py` generates graphs of detected alerts (verified with HTTP/ICMP traffic). |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


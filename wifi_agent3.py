import subprocess
import uuid
import re
import time
import csv
import os
import argparse
import json
import signal
import sys
from langchain.tools import tool
from langchain_ollama import ChatOllama
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain.prompts import ChatPromptTemplate

# Global flag for clean shutdown
shutdown_requested = False
active_processes = []  # Track active subprocesses for cleanup

def signal_handler(sig, frame):
    """Handle Ctrl-C gracefully"""
    global shutdown_requested
    shutdown_requested = True
    print("\n\n[!] Shutdown requested. Cleaning up...")
    # Kill all active subprocesses
    for proc in active_processes:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=2)
        except:
            os.killpg(proc.pid, signal.SIGKILL)
    active_processes.clear()

# Register signal handler
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)  # Also handle SIGTERM for better shutdown

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Autonomous WiFi Scanning Agent")
parser.add_argument("--interface", default=None, help="WiFi interface (e.g., wlan0); auto-detect if not specified")
parser.add_argument("--scan-duration", type=int, default=15, help="Scan duration per cycle in seconds (default: 15)")
parser.add_argument("--csv-output", default="/tmp/scan_results.csv", help="Output CSV file path")
parser.add_argument("--debug", action="store_true", help="Enable debug output")
args = parser.parse_args()

# Configuration
SCAN_DURATION = args.scan_duration
CSV_OUTPUT = args.csv_output
DEBUG = args.debug
ALLOWED_BINARIES = {"airmon-ng", "airodump-ng", "aircrack-ng"}
scan_history = {}

# OUI Database for vendor/firmware approximation
OUI_DATABASE = {
    "00:14:22": "Netgear (known old models, e.g., WNR2000 with CVE-2017-6862)",
    "00:24:B2": "D-Link (check DIR-615/655, CVE-2019-16920)",
    "00:1E:58": "TP-Link (older models like TL-WR841N, CVE-2020-9374)",
    "00:0F:66": "Belkin (e.g., F5D8235-4, WPS vulnerabilities)",
    "00:1A:11": "Asus (check RT-N56U, CVE-2014-9583)",
    "00:14:BF": "Linksys (older WRT54G series, default credentials)",
    "00:18:F3": "ASUS (some models with unpatched firmware)",
    "00:24:56": "Zyxel (e.g., NBG-418N, CVE-2017-6884)",
    "00:26:F2": "Netgear (alternative OUI, older WNDR models)",
    "00:1C:DF": "D-Link (alternative OUI, DIR-300/320 risks)",
    "00:50:F2": "Microsoft (older wireless APs, rare but vulnerable)",
    "00:0D:3A": "Tenda (budget routers, e.g., W302R, WPS issues)",
}

# Cracking difficulty mapping
CRACKING_DIFFICULTY = {
    "Open": "Trivial",
    "WEP": "Easy",
    "WPA-TKIP": "Medium",
    "WPA2-TKIP": "Medium",
    "Potential Weak Passphrase": "Medium to Hard",
    "WPS Enabled": "Medium",
    "Possible Outdated Firmware": "Variable",
    "Strong Encryption": "Hard"
}

def debug_print(msg):
    """Print debug messages if debug mode is enabled"""
    if DEBUG:
        print(f"[DEBUG] {msg}")

def detect_wifi_interface() -> str:
    """Detect available WiFi interfaces using airmon-ng."""
    try:
        result = subprocess.run(["sudo", "airmon-ng"], capture_output=True, text=True, timeout=5)
        output = result.stdout
        debug_print(f"airmon-ng output: {output}")
        # Parse airmon-ng output for interfaces (e.g., wlan0, wlan1)
        interfaces = []
        for line in output.splitlines():
            if 'wlan' in line:  # Include mon interfaces if already in mode
                parts = re.split(r'\s+', line)
                if len(parts) > 1 and parts[1].startswith('wlan'):
                    interfaces.append(parts[1])
        debug_print(f"Detected interfaces: {interfaces}")
        # Select first interface or fall back to user-specified
        if interfaces:
            return interfaces[0]
        return args.interface if args.interface else "wlan0"
    except subprocess.CalledProcessError as e:
        debug_print(f"Error detecting interfaces: {e.stderr}")
        return args.interface if args.interface else "wlan0"

# Set INTERFACE dynamically
INTERFACE = detect_wifi_interface()
print(f"[*] Detected WiFi interface: {INTERFACE}")

# Initialize Ollama LLM
llm = ChatOllama(model="llama3.2:3b", temperature=0)

def run_aircrack_command(command: str, timeout: int = None) -> dict:
    """Execute aircrack suite command safely."""
    binary = command.split()[0]
    if binary not in ALLOWED_BINARIES:
        return {"status": "error", "output": f"Error: Only {', '.join(ALLOWED_BINARIES)} allowed."}
    full_cmd = ["sudo"] + command.split()
    try:
        result = subprocess.run(
            full_cmd, check=True, text=True, capture_output=True, timeout=timeout
        )
        return {"status": "success", "output": result.stdout.strip() or "Command executed."}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "output": f"Error: {e}\nStdout: {e.stdout}\nStderr: {e.stderr}"}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "output": "Command timed out."}

@tool
def setup_monitor_mode(interface: str = INTERFACE) -> dict:
    """Set up monitor mode on the specified WiFi interface using airmon-ng."""
    if not interface:
        interface = INTERFACE
    try:
        # Validate interface
        result = run_aircrack_command("airmon-ng", timeout=5)
        if result["status"] == "success" and interface not in result["output"]:
            return {"status": "error", "output": f"Interface {interface} not found."}
        # Check if already in monitor mode
        if 'mon' in interface:
            return {"status": "success", "output": f"Interface {interface} already in monitor mode.", "interface": interface}
        # Kill interfering processes
        run_aircrack_command("airmon-ng check kill", timeout=5)
        # Start monitor mode
        result = run_aircrack_command(f"airmon-ng start {interface}", timeout=15)
        if result["status"] != "success":
            return {"status": "error", "output": result["output"]}
        # Extract the monitor interface name from output
        output = result["output"]
        match = re.search(r'(\w+mon)', output)
        monitor_interface = match.group(1) if match else f"{interface}mon"  # Fallback
        return {"status": "success", "output": f"Monitor mode enabled on {monitor_interface}.", "interface": monitor_interface}
    except Exception as e:
        return {"status": "error", "output": str(e)}

@tool
def scan_networks(interface: str = INTERFACE, duration: int = SCAN_DURATION) -> list:
    """Scan WiFi networks in monitor mode and identify configurations."""
    if not interface:
        interface = INTERFACE
    if shutdown_requested:
        return [{"status": "error", "message": "Shutdown requested"}]
    scan_id = uuid.uuid4().hex[:8]
    output_file = f"/tmp/airodump_{scan_id}"
    debug_print(f"Starting scan with ID: {scan_id}")
    debug_print(f"Interface: {interface}, Duration: {duration}s")
    proc = None
    csv_file = f"{output_file}-01.csv"
    try:
        # Preexec to ignore SIGINT and set process group
        def preexec():
            os.setpgrp()
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        # Run airodump-ng with CSV output using Popen (since it runs indefinitely)
        cmd = ["sudo", "airodump-ng", interface, "-w", output_file, "--output-format", "csv", "--write-interval", "1"]
        debug_print(f"Running: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=preexec)
        active_processes.append(proc)
        # Sleep in loop to check shutdown_requested
        start_time = time.time()
        while time.time() - start_time < duration and not shutdown_requested:
            time.sleep(1)
        # Terminate the process group
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
        if proc in active_processes:
            active_processes.remove(proc)
        if not os.path.exists(csv_file):
            debug_print(f"CSV file not found: {csv_file}")
            return [{"status": "error", "message": "No scan file created"}]
        debug_print(f"Found CSV file: {csv_file}")
        # Read the CSV file (use sudo cat if permission issue)
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                ap_rows = []
                in_ap_section = False
                for row in reader:
                    if row and 'BSSID' in row[0]:  # Header for APs
                        in_ap_section = True
                        continue
                    if row and 'Station MAC' in row[0]:  # Start of clients, stop
                        in_ap_section = False
                        break
                    if in_ap_section and row:
                        ap_rows.append(row)
        except PermissionError:
            result = subprocess.run(["sudo", "cat", csv_file], capture_output=True, text=True)
            content = result.stdout.splitlines()
            reader = csv.reader(content)
            ap_rows = []
            in_ap_section = False
            for row in reader:
                if row and 'BSSID' in row[0]:
                    in_ap_section = True
                    continue
                if row and 'Station MAC' in row[0]:
                    in_ap_section = False
                    break
                if in_ap_section and row:
                    ap_rows.append(row)
        # Parse AP rows
        nets = []
        for row in ap_rows:
            if len(row) < 14:
                continue
            try:
                bssid = row[0].strip()
                if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', bssid):
                    continue
                channel = row[3].strip()
                privacy = row[5].strip()
                cipher = row[6].strip()
                auth = row[7].strip()
                power = row[8].strip()
                ssid = row[13].strip()
                # Skip very weak signals
                if power and int(power) < -90:
                    continue
                weaknesses = []
                # Check for weaknesses
                if privacy == "OPN":
                    weaknesses.append("Open")
                elif "WEP" in privacy:
                    weaknesses.append("WEP")
                elif "WPA" in privacy:
                    if "TKIP" in cipher:
                        if "WPA2" in privacy:
                            weaknesses.append("WPA2-TKIP")
                        else:
                            weaknesses.append("WPA-TKIP")
                    else:
                        weaknesses.append("Strong Encryption")
                    weaknesses.append("Potential Weak Passphrase")
                oui_info = check_oui(bssid)
                if "Unknown" not in oui_info:
                    weaknesses.append(f"Possible Outdated Firmware: {oui_info}")
                # Calculate cracking difficulty
                difficulties = set(CRACKING_DIFFICULTY.get(w.split(":")[0].strip(), "Variable") for w in weaknesses)
                nets.append({
                    "ssid": ssid if ssid else "Hidden",
                    "bssid": bssid,
                    "weaknesses": weaknesses,
                    "channel": channel,
                    "power": power,
                    "cracking_difficulty": "; ".join(difficulties) if difficulties else "Hard"
                })
                debug_print(f"Found network: {ssid} ({bssid}) - {weaknesses}")
            except Exception as e:
                debug_print(f"Error parsing row: {e}")
        if nets:
            debug_print(f"Total networks found: {len(nets)}")
            return nets
        return [{"status": "success", "message": "No networks found"}]
    except Exception as e:
        if proc and proc in active_processes:
            active_processes.remove(proc)
        subprocess.run(["sudo", "rm", "-f"] + [f"{output_file}*"])
        return [{"status": "error", "message": str(e)}]
    finally:
        subprocess.run(["sudo", "rm", "-f"] + [f"{output_file}*"])

def check_oui(bssid: str) -> str:
    """Check BSSID OUI for potential outdated firmware."""
    oui = bssid[:8].upper()
    return OUI_DATABASE.get(oui, "Unknown vendor (check firmware manually)")

def write_scan_history_to_csv(history: dict, output_file: str = CSV_OUTPUT):
    """Write scan_history to CSV if non-empty."""
    if not history:
        return "No data to write."
    try:
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Cycle", "SSID", "BSSID", "Channel", "Power", "Weaknesses", "Difficulty"])
            for cycle_id, data in history.items():
                for net in data.get("weak_networks", []):
                    writer.writerow([
                        cycle_id[:8],
                        net.get("ssid", "Unknown"),
                        net.get("bssid", "N/A"),
                        net.get("channel", "N/A"),
                        net.get("power", "N/A"),
                        "; ".join(net.get("weaknesses", [])),
                        net.get("cracking_difficulty", "N/A")
                    ])
        return f"Results written to {output_file}"
    except Exception as e:
        return f"Error writing CSV: {e}"

# Agent Setup
system_prompt = f"""
You are a WiFi security research agent operating in a controlled lab environment. Your goal is to autonomously perform WiFi scan cycles to identify networks, their security types, and assess cracking difficulties.
IMPORTANT INSTRUCTIONS:
1. Always start by calling setup_monitor_mode with interface='{INTERFACE}' to enable monitor mode if not already enabled. It returns the monitor interface name in the 'interface' key - use this for all subsequent calls.
2. Then call scan_networks with the monitor-mode interface and duration={SCAN_DURATION} to scan for networks.
3. Do not attempt any handshake captures or deauth attacks. Focus only on passive scanning and analysis.
4. Finally, output the JSON summary directly as your final response. Do not use any tools for the summary - just return the JSON.
The scan_networks function returns a list of dictionaries with keys: ssid, bssid, weaknesses, channel, power, cracking_difficulty. If it returns an error, handle it gracefully in your summary.
Your final response must be ONLY a valid JSON object with these keys:
- weak_networks: array of all networks found (include all, not just weak, for full analysis; empty array if error)
- summary: object containing 'summary' (brief text, e.g., "Found X networks with varying security.") and 'next_steps' (array of recommended actions, e.g., ["Review cracking difficulties"])
Be concise and focus on ethical lab testing. If scan fails, set weak_networks to [] and note in summary.
"""
prompt = ChatPromptTemplate.from_messages([
    ("system", system_prompt),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])
tools = [setup_monitor_mode, scan_networks]  # Removed capture_handshake
agent = create_tool_calling_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=DEBUG)

# Main execution
print(f"[*] Autonomous WiFi Scanning Agent Started")
print(f"[*] Interface: {INTERFACE}, Scan Duration: {SCAN_DURATION}s")
print(f"[*] Results will be saved to: {CSV_OUTPUT}")
print(f"[*] Debug mode: {'ON' if DEBUG else 'OFF'}")
print(f"[*] Press Ctrl+C to stop\n")
cycle_count = 0
try:
    while not shutdown_requested:
        cycle_count += 1
        cycle_id = str(uuid.uuid4())
        print(f"\n{'='*60}")
        print(f"[*] SCAN CYCLE {cycle_count} (ID: {cycle_id[:8]})")
        print(f"{'='*60}")
        if shutdown_requested:
            break
        try:
            response = agent_executor.invoke({"input": "Perform a WiFi scan cycle."})
            # Extract and parse JSON from response
            output_text = response.get('output', '')
            # Improved regex for multi-line JSON
            json_match = re.search(r'\{[\s\S]*\}', output_text)
            if json_match:
                try:
                    parsed = json.loads(json_match.group(0))
                    weak_nets = parsed.get("weak_networks", [])
                    summary = parsed.get("summary", {})
                    # Store in history
                    scan_history[cycle_id] = {
                        "weak_networks": weak_nets
                    }
                    # Display results with formatting
                    print(f"\n[+] RESULTS")
                    print(f" {'-'*56}")
                    if weak_nets:
                        print(f" Found {len(weak_nets)} network(s):\n")
                        for i, net in enumerate(weak_nets, 1):
                            print(f" [{i}] SSID: {net.get('ssid', 'Hidden')}")
                            print(f"     BSSID: {net.get('bssid')}")
                            print(f"     Channel: {net.get('channel')} | Power: {net.get('power', 'N/A')} dBm")
                            print(f"     Weaknesses: {', '.join(net.get('weaknesses', []))}")
                            print(f"     Cracking Difficulty: {net.get('cracking_difficulty')}")
                            print()
                    else:
                        print(" No networks detected")
                    if summary:
                        print(f" Summary: {summary.get('summary', 'N/A')}")
                        if summary.get('next_steps'):
                            print(f" Next Steps:")
                            for step in summary.get('next_steps', []):
                                print(f" • {step}")
                    print(f" {'-'*56}")
                except json.JSONDecodeError as e:
                    print(f"[-] Failed to parse JSON: {e}")
                    if DEBUG:
                        print(f"[DEBUG] Raw output: {output_text[:500]}...")
            else:
                print(f"[-] No JSON found in response")
                if DEBUG:
                    print(f"[DEBUG] Raw output: {output_text[:500]}...")
        except KeyboardInterrupt:
            shutdown_requested = True
        except Exception as e:
            print(f"[-] Error in scan cycle: {e}")
            if DEBUG:
                import traceback
                traceback.print_exc()
        if not shutdown_requested:
            print(f"\n[*] Waiting 10 seconds before next cycle...")
            try:
                for i in range(10):
                    if shutdown_requested:
                        break
                    time.sleep(1)
            except KeyboardInterrupt:
                shutdown_requested = True
except KeyboardInterrupt:
    shutdown_requested = True
finally:
    print("\n\n[*] Shutting down...")
    # Save results
    if scan_history:
        result = write_scan_history_to_csv(scan_history)
        print(f"[*] {result}")
    else:
        print("[*] No data to save")
    # Stop monitor mode
    print("[*] Stopping monitor mode...")
    try:
        run_aircrack_command(f"airmon-ng stop {INTERFACE}", timeout=5)  # Use INTERFACE (might have 'mon')
        print("[*] Monitor mode stopped")
    except:
        pass
    # Clean up temporary files
    print("[*] Cleaning up temporary files...")
    try:
        subprocess.run(["sudo", "rm", "-f", "/tmp/airodump_*", "/tmp/capture_*"], timeout=3)
    except:
        pass
    # Additional cleanup for lingering processes
    print("[*] Killing any lingering airodump-ng processes...")
    subprocess.run(["sudo", "killall", "-9", "airodump-ng"], check=False)
    print("[*] Shutdown complete")
    sys.exit(0)

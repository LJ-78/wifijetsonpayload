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
import requests  # Added for Kismet API
from langchain.tools import tool
from langchain_ollama import ChatOllama
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain.prompts import ChatPromptTemplate

# Global flag for clean shutdown
shutdown_requested = False
active_processes = []  # Track active subprocesses for cleanup

# Kismet API configuration (assume running locally; adjust as needed)
KISMET_URL = "http://localhost:2501"
KISMET_API_TOKEN = "D935E8D1A11B7BC7901A0391F21D8E44"  # Add your API token here; e.g., "your_long_token_string"

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
parser = argparse.ArgumentParser(description="Autonomous WiFi Scanning Agent with Kismet")
parser.add_argument("--scan-duration", type=int, default=15, help="Scan duration per cycle in seconds (default: 15)")
parser.add_argument("--csv-output", default="/tmp/scan_results.csv", help="Output CSV file path")
parser.add_argument("--debug", action="store_true", help="Enable debug output")
args = parser.parse_args()

# Configuration
SCAN_DURATION = args.scan_duration
CSV_OUTPUT = args.csv_output
DEBUG = args.debug
scan_history = {}

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

# Initialize Ollama LLM
llm = ChatOllama(model="llama3.2:3b", temperature=0)

@tool
def scan_networks(duration: int = SCAN_DURATION) -> list:
    """Scan WiFi networks using Kismet API and identify configurations."""
    if shutdown_requested:
        return [{"status": "error", "message": "Shutdown requested"}]
    debug_print(f"Starting Kismet API scan, Duration: {duration}s")
    time.sleep(duration)  # Simulate scan time; in practice, Kismet runs continuously
    try:
        headers = {"Cookie": f"KISMET={KISMET_API_TOKEN}"} if KISMET_API_TOKEN else {}
        payload = {
            "fields": ["dot11.ssidgroup.ssid", "dot11.ssidgroup.crypt_set", "dot11.ssidgroup.crypt_string"],
            "length": 0  # 0 for all
        }
        response = requests.post(f"{KISMET_URL}/phy/phy80211/ssids/views/ssids.json", headers=headers, json=payload)
        response.raise_for_status()
        ssids = response.json()
        nets = []
        for entry in ssids:
            try:
                ssid = entry.get('dot11.ssidgroup.ssid', 'Hidden')
                crypt_set = entry.get('dot11.ssidgroup.crypt_set', 0)
                crypt_string = entry.get('dot11.ssidgroup.crypt_string', 'Unknown')
                weaknesses = [crypt_string] if crypt_string != "Unknown" else []
                if crypt_set == 0:
                    weaknesses.append("Open")
                elif crypt_set & 0x1:
                    weaknesses.append("WEP")
                elif crypt_set & 0x4:  # WPA bit
                    if crypt_set & 0x100:  # TKIP
                        weaknesses.append("WPA-TKIP" if not (crypt_set & 0x800) else "WPA2-TKIP")
                    else:
                        weaknesses.append("Strong Encryption")
                    weaknesses.append("Potential Weak Passphrase")
                difficulties = set(CRACKING_DIFFICULTY.get(w.split(":")[0].strip(), "Variable") for w in weaknesses)
                net = {
                    "ssid": ssid,
                    "weaknesses": weaknesses,
                    "cracking_difficulty": "; ".join(difficulties) if difficulties else "Hard"
                }
                nets.append(net)
                debug_print(f"Found network: {ssid} - {weaknesses}")
            except Exception as e:
                debug_print(f"Error parsing SSID entry: {e}")
        if nets:
            debug_print(f"Total networks found: {len(nets)}")
            return nets
        return [{"status": "success", "message": "No networks found"}]
    except requests.RequestException as e:
        return [{"status": "error", "message": str(e)}]

def write_scan_history_to_csv(history: dict, output_file: str = CSV_OUTPUT):
    """Write scan_history to CSV if non-empty."""
    if not history:
        return "No data to write."
    try:
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Cycle", "SSID", "Weaknesses", "Cracking Difficulty"])
            for cycle_id, data in history.items():
                for net in data.get("weak_networks", []):
                    writer.writerow([
                        cycle_id[:8],
                        net.get("ssid", "Unknown"),
                        "; ".join(net.get("weaknesses", [])),
                        net.get("cracking_difficulty", "N/A")
                    ])
        return f"Results written to {output_file}"
    except Exception as e:
        return f"Error writing CSV: {e}"

# Agent Setup
system_prompt = f"""
You are a WiFi security research agent operating in a controlled lab environment. Your goal is to autonomously perform WiFi scan cycles to identify networks, their security types, and assess cracking difficulties using Kismet API.
IMPORTANT INSTRUCTIONS:
1. Call scan_networks with duration={SCAN_DURATION} to scan for networks using Kismet API (assume Kismet is running).
2. Do not attempt any captures or attacks. Focus only on passive scanning and analysis.
3. If the scan returns an error or no networks, set weak_networks to [] and note the error in the summary.
4. Do not hallucinate or invent network data. Use only real data from tool calls. If errors occur, reflect them accurately in the JSON.
5. Finally, output the JSON summary directly as your final response. Do not use any tools for the summary - just return the JSON.
The scan_networks function returns a list of dictionaries with keys: ssid, weaknesses, cracking_difficulty. If it returns an error dict, handle it gracefully.
Your final response must be ONLY a valid JSON object with these keys:
- weak_networks: array of all networks found (include all, not just weak, for full analysis; empty array if error or no networks)
- summary: object containing 'summary' (brief text, e.g., "Found X networks with varying security.") and 'next_steps' (array of recommended actions, e.g., ["Review cracking difficulties", "If WEP found, consider capturing traffic in lab"])
Be concise and focus on ethical lab testing. If scan fails, set weak_networks to [] and note in summary.
"""
prompt = ChatPromptTemplate.from_messages([
    ("system", system_prompt),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])
tools = [scan_networks]
agent = create_tool_calling_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=DEBUG)

# Main execution
print(f"[*] Autonomous WiFi Scanning Agent Started with Kismet")
print(f"[*] Scan Duration: {SCAN_DURATION}s")
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
    print("[*] Shutdown complete")
    sys.exit(0)

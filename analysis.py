# Updated analysis.py - Enhanced network selection with sorting and MAC display
from typing import List, Dict, Tuple
import inquirer  # pip install inquirer
import sys
from datetime import datetime

def get_difficulty_score(security: str) -> int:
    security = security.upper()
    if "OPEN" in security:
        return 0
    elif "WEP" in security:
        return 1
    elif "TKIP" in security:
        return 2
    elif "WPA2" in security and "AES" in security:
        return 3
    elif "WPA3" in security:
        return 4
    else:
        return 4

def find_easiest_and_hardest(networks: List[Dict]) -> Tuple[Dict, Dict]:
    if not networks:
        raise ValueError("No networks found")
    
    # Filter for access points only
    access_points = [n for n in networks if n.get('type', '').lower() == 'ap' or n.get('type', '').lower() == 'access point']
    
    if not access_points:
        print("[!] No access points found, using all networks")
        access_points = networks
    
    def signal_for_sort(n: Dict) -> float:
        return n["signal"] if n["signal"] is not None else -1000.0
    
    easiest = min(access_points, key=lambda n: (get_difficulty_score(n["security"]), -signal_for_sort(n)))
    hardest = max(access_points, key=lambda n: (get_difficulty_score(n["security"]), signal_for_sort(n)))
    
    return easiest, hardest


def select_network_for_crack(networks: Dict[str, Dict]) -> Dict:
    """Prompt user to select network to crack from analyzed options"""
    
    # Convert dict of dicts to list of dicts for processing
    network_list = list(networks.values())
    
    # Filter for access points only
    access_points = [n for n in network_list if n.get('type', '').lower() == 'ap' or n.get('type', '').lower() == 'access point']
    
    if not access_points:
        print("[!] No access points found, showing all networks")
        access_points = network_list
    
    print(f"\n{'='*60}")
    print("ANALYZED NETWORK OPTIONS")
    print(f"{'='*60}")
    
    choices = []
    for n in access_points:
        # Format: SSID | MAC | Security | Signal
        choice_text = f"{n['ssid']:<25} | {n.get('mac', 'Unknown MAC'):<17} | {n['security']:<15} | {n['signal']:>-4}dBm"
        choices.append(choice_text)
    
    choices.append(">>> QUIT <<<")

    questions = [
        inquirer.List('network',
                    message="Select network to run aircrack against:",
                    choices=choices,
                    carousel=True)
    ]
    answers = inquirer.prompt(questions)
    
    if answers is None:
        print("\n[!] Selection cancelled by user. Exiting...")
        sys.exit(0)
    
    # Handle quit option
    selection = answers['network']
    if selection == ">>> QUIT <<<":
        print("\n[!] Quitting...")
        sys.exit(0)

    # Find selected network by MAC address (more reliable than SSID)
    selected_mac = selection.split('|')[1].strip()
    selected = next(n for n in access_points if n.get('mac', '') == selected_mac)
    
    print(f"\n[+] Selected: {selected['ssid']} ({selected.get('mac', 'Unknown MAC')})")
    print(f"    Security: {selected['security']}")
    print(f"    Signal: {selected['signal']}dBm")
    print(f"    Channel: {selected.get('channel', 'Unknown')}")
    
    return selected


def select_from_all_networks(networks: List[Dict]) -> Dict:
    """Prompt user to select from all available networks, sorted by time and signal"""

    # Filter for access points only
    access_points = [n for n in networks if n.get('type', '').lower() == 'ap' or n.get('type', '').lower() == 'access point']

    if not access_points:
        print("[!] No access points found, showing all networks")
        access_points = networks

    print(f"\n{'='*80}")
    print(f"ALL ACCESS POINTS ({len(access_points)} found)")
    print(f"{'='*80}")
    
    # Sort by last_time (most recent first), then by signal strength (strongest first)
    def sort_key(network):
        # Get timestamp - handle different possible field names
        timestamp = network.get('last_time', network.get('lastseen', network.get('timestamp', 0)))
        
        # Convert to comparable format if it's a string
        if isinstance(timestamp, str):
            try:
                # Try to parse ISO format or unix timestamp
                if 'T' in timestamp:  # ISO format
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()
                else:
                    timestamp = float(timestamp)
            except:
                timestamp = 0
        
        # Signal strength (higher/less negative is better)
        signal = network.get('signal', -1000)
        if signal is None:
            signal = -1000
        
        # Return tuple for sorting: negative timestamp for descending order, negative signal for descending
        return (-timestamp, -signal)
    
    # Sort the networks
    sorted_networks = sorted(access_points, key=sort_key)
    
    # Display header
    print(f"\n{'SSID':<25} | {'MAC Address':<17} | {'Security':<15} | {'Signal':>7} | {'Channel':>7} | {'Last Seen'}")
    print("-" * 100)
    
    # Create choices with detailed information
    choices = []
    for i, n in enumerate(sorted_networks, 1):
        # Get timestamp and format it
        timestamp = n.get('last_time', n.get('lastseen', n.get('timestamp', 'Unknown')))
        if isinstance(timestamp, (int, float)) and timestamp > 0:
            time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
        elif isinstance(timestamp, str) and timestamp != 'Unknown':
            try:
                if 'T' in timestamp:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    time_str = dt.strftime('%H:%M:%S')
                else:
                    time_str = timestamp[:8] if len(timestamp) >= 8 else timestamp
            except:
                time_str = 'Recent'
        else:
            time_str = 'Unknown'
        
        # Format the choice text with all information
        ssid = n.get('ssid', 'Hidden')[:24]  # Truncate long SSIDs
        mac = n.get('mac', 'Unknown MAC')
        security = n.get('security', 'Unknown')[:14]  # Truncate long security strings
        signal = n.get('signal', -999)
        channel = n.get('channel', '?')
        
        choice_text = f"{i:3}. {ssid:<24} | {mac:<17} | {security:<15} | {signal:>-4}dBm | Ch {channel:>3} | {time_str}"
        choices.append(choice_text)
    
    # Add quit option
    choices.append(">>> QUIT <<<")
    
    # Show statistics
    print(f"\nStatistics:")
    print(f"  Total APs: {len(sorted_networks)}")
    
    # Count by security type
    security_counts = {}
    for n in sorted_networks:
        sec_type = n.get('security', 'Unknown').split()[0] if n.get('security') else 'Unknown'
        security_counts[sec_type] = security_counts.get(sec_type, 0) + 1
    
    print(f"  Security types: {', '.join(f'{k}:{v}' for k, v in security_counts.items())}")
    
    # Signal strength ranges
    strong = sum(1 for n in sorted_networks if n.get('signal', -1000) > -50)
    medium = sum(1 for n in sorted_networks if -70 <= n.get('signal', -1000) <= -50)
    weak = sum(1 for n in sorted_networks if n.get('signal', -1000) < -70)
    print(f"  Signal strength: Strong(>{-50}dBm):{strong}, Medium({-70} to {-50}dBm):{medium}, Weak(<{-70}dBm):{weak}")
    print("")
    
    questions = [
        inquirer.List('network',
                    message="Select network to run aircrack against (sorted by time & signal):",
                    choices=choices,
                    carousel=True)
    ]
    answers = inquirer.prompt(questions)
    
    # Handle cancellation
    if answers is None:
        print("\n[!] Selection cancelled by user. Exiting...")
        sys.exit(0)
    
    # Handle quit option
    selection = answers['network']
    if selection == ">>> QUIT <<<":
        print("\n[!] Quit selected. Exiting...")
        sys.exit(0)
    
    # Extract MAC address from the selection (it's between the first and second |)
    try:
        parts = selection.split('|')
        selected_mac = parts[1].strip()
        selected = next(n for n in sorted_networks if n.get('mac', '') == selected_mac)
    except:
        # Fallback to index-based selection if parsing fails
        idx = int(selection.split('.')[0]) - 1
        selected = sorted_networks[idx]
    
    print(f"\n[+] Selected: {selected.get('ssid', 'Unknown')} ({selected.get('mac', 'Unknown MAC')})")
    print(f"    Security: {selected.get('security', 'Unknown')}")
    print(f"    Signal: {selected.get('signal', -999)}dBm")
    print(f"    Channel: {selected.get('channel', 'Unknown')}")
    
    # Show additional details if available
    if 'manufacturer' in selected:
        print(f"    Manufacturer: {selected['manufacturer']}")
    if 'frequency' in selected:
        print(f"    Frequency: {selected['frequency']} MHz")
    if 'clients' in selected or 'client_count' in selected:
        client_count = selected.get('clients', selected.get('client_count', 0))
        print(f"    Connected Clients: {client_count}")
    
    return selected


def search_networks_by_ssid(networks: List[Dict]) -> Dict:
    """Search and select networks by SSID name"""

    # Filter for access points only
    access_points = [n for n in networks if n.get('type', '').lower() == 'ap' or n.get('type', '').lower() == 'access point']

    if not access_points:
        print("[!] No access points found, showing all networks")
        access_points = networks

    print(f"\n{'='*80}")
    print(f"SEARCH NETWORKS BY SSID")
    print(f"{'='*80}")

    # Prompt for search term
    search_questions = [
        inquirer.Text('search_term',
                    message="Enter SSID search term (case-insensitive, partial match)")
    ]
    search_answer = inquirer.prompt(search_questions)

    if search_answer is None or not search_answer['search_term'].strip():
        print("[!] No search term provided. Exiting...")
        sys.exit(0)

    search_term = search_answer['search_term'].strip().lower()
    original_count = len(access_points)

    # Filter networks by search term
    filtered_networks = [n for n in access_points if search_term in n.get('ssid', '').lower()]

    print(f"[*] Found {len(filtered_networks)} networks matching '{search_term}' (from {original_count} total)")

    if not filtered_networks:
        print("[!] No networks match your search. Exiting...")
        sys.exit(0)

    # Sort by last_time (most recent first), then by signal strength (strongest first)
    def sort_key(network):
        # Get timestamp - handle different possible field names
        timestamp = network.get('last_time', network.get('lastseen', network.get('timestamp', 0)))

        # Convert to comparable format if it's a string
        if isinstance(timestamp, str):
            try:
                # Try to parse ISO format or unix timestamp
                if 'T' in timestamp:  # ISO format
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()
                else:
                    timestamp = float(timestamp)
            except:
                timestamp = 0

        # Signal strength (higher/less negative is better)
        signal = network.get('signal', -1000)
        if signal is None:
            signal = -1000

        # Return tuple for sorting: negative timestamp for descending order, negative signal for descending
        return (-timestamp, -signal)

    # Sort the filtered networks
    sorted_networks = sorted(filtered_networks, key=sort_key)

    # Display header
    print(f"\n{'SSID':<25} | {'MAC Address':<17} | {'Security':<15} | {'Signal':>7} | {'Channel':>7} | {'Last Seen'}")
    print("-" * 100)

    # Create choices with detailed information
    choices = []
    for i, n in enumerate(sorted_networks, 1):
        # Get timestamp and format it
        timestamp = n.get('last_time', n.get('lastseen', n.get('timestamp', 'Unknown')))
        if isinstance(timestamp, (int, float)) and timestamp > 0:
            time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
        elif isinstance(timestamp, str) and timestamp != 'Unknown':
            try:
                if 'T' in timestamp:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    time_str = dt.strftime('%H:%M:%S')
                else:
                    time_str = timestamp[:8] if len(timestamp) >= 8 else timestamp
            except:
                time_str = 'Recent'
        else:
            time_str = 'Unknown'

        # Format the choice text with all information
        ssid = n.get('ssid', 'Hidden')[:24]  # Truncate long SSIDs
        mac = n.get('mac', 'Unknown MAC')
        security = n.get('security', 'Unknown')[:14]  # Truncate long security strings
        signal = n.get('signal', -999)
        channel = n.get('channel', '?')

        choice_text = f"{i:3}. {ssid:<24} | {mac:<17} | {security:<15} | {signal:>-4}dBm | Ch {channel:>3} | {time_str}"
        choices.append(choice_text)

    # Add quit option
    choices.append(">>> QUIT <<<")

    questions = [
        inquirer.List('network',
                    message=f"Select network from search results (sorted by time & signal):",
                    choices=choices,
                    carousel=True)
    ]
    answers = inquirer.prompt(questions)

    # Handle cancellation
    if answers is None:
        print("\n[!] Selection cancelled by user. Exiting...")
        sys.exit(0)

    # Handle quit option
    selection = answers['network']
    if selection == ">>> QUIT <<<":
        print("\n[!] Quit selected. Exiting...")
        sys.exit(0)

    # Extract MAC address from the selection (it's between the first and second |)
    try:
        parts = selection.split('|')
        selected_mac = parts[1].strip()
        selected = next(n for n in sorted_networks if n.get('mac', '') == selected_mac)
    except:
        # Fallback to index-based selection if parsing fails
        idx = int(selection.split('.')[0]) - 1
        selected = sorted_networks[idx]

    print(f"\n[+] Selected: {selected.get('ssid', 'Unknown')} ({selected.get('mac', 'Unknown MAC')})")
    print(f"    Security: {selected.get('security', 'Unknown')}")
    print(f"    Signal: {selected.get('signal', -999)}dBm")
    print(f"    Channel: {selected.get('channel', 'Unknown')}")

    return selected


# Helper function to format network details
def format_network_details(network: Dict) -> str:
    """Format network details for display"""
    details = []
    details.append(f"SSID: {network.get('ssid', 'Hidden')}")
    details.append(f"MAC: {network.get('mac', 'Unknown')}")
    details.append(f"Security: {network.get('security', 'Unknown')}")
    details.append(f"Signal: {network.get('signal', -999)}dBm")
    details.append(f"Channel: {network.get('channel', 'Unknown')}")
    
    if 'manufacturer' in network:
        details.append(f"Manufacturer: {network['manufacturer']}")
    if 'frequency' in network:
        details.append(f"Frequency: {network['frequency']} MHz")
    
    return '\n'.join(details)


# Export the main functions
__all__ = ['find_easiest_and_hardest', 'select_network_for_crack', 'select_from_all_networks', 'search_networks_by_ssid', 'get_difficulty_score']



# # Updated analysis.py - Add network selection
# from typing import List, Dict, Tuple
# import inquirer  # pip install inquirer
# import sys

# def get_difficulty_score(security: str) -> int:
#     security = security.upper()
#     if "OPEN" in security:
#         return 0
#     elif "WEP" in security:
#         return 1
#     elif "TKIP" in security:
#         return 2
#     elif "WPA2" in security and "AES" in security:
#         return 3
#     elif "WPA3" in security:
#         return 4
#     else:
#         return 4

# def find_easiest_and_hardest(networks: List[Dict]) -> Tuple[Dict, Dict]:
#     if not networks:
#         raise ValueError("No networks found")
    
#     def signal_for_sort(n: Dict) -> float:
#         return n["signal"] if n["signal"] is not None else -1000.0
    
#     easiest = min(networks, key=lambda n: (get_difficulty_score(n["security"]), -signal_for_sort(n)))
#     hardest = max(networks, key=lambda n: (get_difficulty_score(n["security"]), signal_for_sort(n)))
    
#     return easiest, hardest


# def select_network_for_crack(networks: Dict[str, Dict]) -> Dict:
#     """Prompt user to select network to crack"""
    
#     # Convert dict of dicts to list of dicts for processing
#     network_list = list(networks.values())
    
#     choices=[f"{n['ssid']} ({n['security']}, {n['signal']}dBm)" for n in network_list]
#     choices.append(">>QUIT<<")

#     questions = [
#         inquirer.List('network',
#                     message="Select network to run aircrack against:",
#                     # choices=[f"{n['ssid']} ({n['security']}, {n['signal']}dBm)" for n in network_list],
#                     choices=choices,
#                     carousel=True)
#     ]
#     answers = inquirer.prompt(questions)
#     if answers is None:
#         print("\n[!] Selction cancelled by user. Exiting...")
#         sys.exit(0)


    
#     # Find selected network
#     selection = answers['network']
#     if selection == ">>QUIT<<":
#         print("\n[!] quiting...")
#         sys.exit(0)

#     selected_ssid = selection.split(' (')[0]
#     selected = next(n for n in network_list if n['ssid'] == selected_ssid)
    
#     print(f"\nSelected: {selected['ssid']} - {selected['security']}")
#     return selected

# def select_from_all_networks(networks: List[Dict]) -> Dict:
#     """Prompt user to select from all available networks"""
#     print(f"\nShowing all {len(networks)} networks:")
    
#     # Create choices with quit option
#     choices = [f"{n['ssid']} ({n['security']}, {n['signal']}dBm)" for n in networks]
#     choices.append(">>> QUIT <<<")
    
#     questions = [
#         inquirer.List('network',
#                     message="Select network to run aircrack against:",
#                     choices=choices,
#                     carousel=True)
#     ]
#     answers = inquirer.prompt(questions)
    
#     # Handle cancellation
#     if answers is None:
#         print("\n[!] Selection cancelled by user. Exiting...")
#         sys.exit(0)
    
#     # Handle quit option
#     selection = answers['network']
#     if selection == ">>> QUIT <<<":
#         print("\n[!] Quit selected. Exiting...")
#         sys.exit(0)
    
#     # Find selected network
#     selected_ssid = selection.split(' (')[0]
#     selected = next(n for n in networks if n['ssid'] == selected_ssid)
    
#     print(f"\nSelected: {selected['ssid']} - {selected['security']}")
#     return selected


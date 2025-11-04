# main.py
import getpass
import signal
import sys
from kismet_utils import get_kismet_session
from graph import build_graph
from typing import Dict
from langchain_core.messages import HumanMessage

def signal_handler(sig, frame):
    """Handle Crtlc gracefully"""
    status("\n\n[!] crtl+x detected. Exiting...")
    sys.exit(0)

def status(msg: str):
    # \r = carriage return to column 0
    # \033[K = clear from cursor to end of line
    sys.stdout.write("\r\033[K" + msg + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    """register the handler for crtl c"""
    signal.signal(signal.SIGINT, signal_handler)

    try:
        username = input("Enter Kismet username: ")
        password = getpass.getpass("Enter Kismet password: ")
        kismet_session = get_kismet_session(username, password)
        
        graph = build_graph()
        
        initial_state: Dict = {
            "messages": [HumanMessage(content="Run wireless survey and analysis")],
            "kismet_session": kismet_session,
            "networks": [],
            "analysis": {},
            "selected_network": {},
            "crack_result": {}
        }
        
        result = graph.invoke(initial_state)
        # status("RESULT: ", result)
        
        status("\n" + "="*50)
        status("CRACK RESULTS:")
        status("="*50)
        status(f"Selected Network: {result['selected_network']['ssid']}")
        status(f"Security: {result['selected_network']['security']}")
        status(f"Signal: {result['selected_network']['signal']}dBm")
    
        # Check if crack_result exists and is an AircrackResult object
        if result.get('crack_result') and hasattr(result['crack_result'], 'output'):
            status(f"\nCrack Output: {result['crack_result'].output}")
            status(f"Success: {result['crack_result'].success}")
            if result['crack_result'].error:
                status(f"Error: {result['crack_result'].error}")
        else:
            status("\n[!] No crack result available") 
    
    
    except KeyboardInterrupt:
        status("\n\n[!] Interrupted. Exiting....")
        sys.exit(0)
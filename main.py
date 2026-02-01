
import time
from modules import scanner, sniffer, stego

def run_mission():
    print("[*] Phase 1: Initiating Network Scan...")
    scan_results = scanner.run_threaded_scan("192.168.1.1")
    
    print("[*] Phase 2: Sniffing Network Traffic for 10 seconds...")
    sniff_results = sniffer.capture_packets(timeout=10)
    
    # Combine data
    secret_message = f"---SCAN DATA---\n{scan_results}\n---SNIFF DATA---\n{sniff_results}"
    
    print("[*] Phase 3: Exfiltrating Data via Steganography...")
    stego.hide_data("assets/cover.png", secret_message, "output_evidence.png")
    
    print("[SUCCESS] Intelligence hidden in 'output_evidence.png'. Operation Complete.")

if __name__ == "__main__":
    run_mission()

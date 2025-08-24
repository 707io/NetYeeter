# NetYeeter Wi-Fi Deauth Tool 

NetYeeter is a Wi-Fi deauthentication tool designed to disconnect devices from a target network. With features like MAC randomization, real-time scanning, and support for tools like `mdk4` and `aireplay-ng`, it’s your ultimate "Bye-Fi" weapon! Perfect for testing your own networks or learning about Wi-Fi security. Just remember: with great power comes great responsibility!

## Features 🛠️
- **Monitor Mode** : Enables monitor mode on your Wi-Fi interface.
- **MAC Randomization** : Spoofs your MAC address to stay under the radar.
- **Real-Time Scanning** : Scans for networks and devices in real-time.
- **Deauthentication Attack** : Kicks devices off a network using `mdk4` or `aireplay-ng`.
- **Cleanup** : Restores your interface to its original state after the attack.

## Installation 💾
1. Clone the repository:
```bash
git clone https://github.com/707io/NetYeeter.git
```
2. Navigate to the project folder:
```bash
cd NetYeeter
```
3. Run the script:
```bash
sudo python3 netyeeter.py
```

## How to Use 🚀
1. Run the script: `sudo python3 netyeeter.py` 
2. Select your Wi-Fi interface
3. Scan for nearby networks
4. Pick a target and choose your weapon (`mdk4` or `aireplay-ng`)
5. Launch the attack

## Requirements ⚙️
- `aircrack-ng` 
- `iw` 
- `mdk3`/`mdk4` 
- `macchanger` 

## Disclaimer ⚠️
This tool is for **educational purposes only**! Misuse is illegal and unethical. Always get permission before testing on any network. Stay ethical.

---

## 🏷️ Credit

Made by **707** ([github.com/707io](https://github.com/707io))



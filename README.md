# IOC 12 – Wi-Fi Impersonation and WPA2/WPA3 Handshake Capture

This case study documents a structured investigation into a wireless impersonation attack where an adversary deploys a rogue access point (evil twin) to mimic a legitimate SSID. The attack enables the capture of WPA2/WPA3 four-way handshake traffic, often followed by offline brute-force password recovery or credential harvesting through fake captive portals.

## Summary

The attacker exploits the trust-based behavior of endpoint devices that auto-connect to known SSIDs. By broadcasting a stronger or closer signal under the same network name, the attacker tricks devices into initiating a legitimate-looking wireless session. This results in the silent capture of the handshake process used to negotiate encryption keys. When credentials are weak, the handshake may later be cracked offline, granting the attacker persistent wireless access.

## Key Indicators of Compromise (IOCs)

- Rogue access point beaconing with identical SSID
- Captured WPA2/WPA3 four-way handshake traffic in PCAP files
- Unusual wireless roaming behavior in endpoint logs
- EDR or SIEM alerts for DNS anomalies or process activity following connection to unknown networks

## Triage Type

**Host-Based Indicator of Compromise**

## Triage Protocol

1. **Windows Event Logs**
   - WLAN AutoConfig events (e.g., Event ID 8001) reflecting SSID transitions or unexpected associations  
2. **EDR Telemetry**
   - Detected network adapter changes or suspicious wireless profile activity  
3. **File System and Registry Inspection**
   - Stored SSID profiles with abnormal parameters or timestamps  
4. **Volatile Memory Capture**
   - Live extraction of connected SSIDs, pre-shared keys (PSKs), or injected payload artifacts  

## OS Layer Relevance

- **Layer 6 – Network Communication Context** (primary target)
- **Layer 1 – Process Execution** (payload activation)
- **Layer 2 – Startup/Persistence** (follow-up implant)
  
## OSI Layer Involvement

- **Layer 1:** Wireless signal broadcasting (RF manipulation)  
- **Layer 2:** MAC spoofing and SSID mimicry  
- **Layer 4:** TLS session interference (e.g., captive portal downgrade)  
- **Layer 7:** Browser-based phishing via fake login portals  

## Tools Referenced

| Tool              | Purpose                                             |
|-------------------|-----------------------------------------------------|
| airbase-ng        | Rogue AP creation                                   |
| airodump-ng       | Capture WPA handshake traffic                       |
| hashcat           | Brute-force cracking of WPA handshake offline       |
| hostapd / Wi-Fi Pineapple | Commercial/flexible wireless impersonation   |
| SIEM & EDR        | Behavior correlation and detection telemetry        |

## Defensive Response

- Capture and review wireless PCAPs to verify rogue beaconing behavior  
- Monitor NetFlow and DNS traffic from client devices after connection attempts  
- Use 802.1X and certificate-based Wi-Fi authentication when possible  
- Harden SSID broadcast settings and restrict open association policies  
- Isolate and re-image compromised hosts; rotate shared keys  

## Educational Addendum

**WPA2/WPA3 Four-Way Handshake Overview**  
A cryptographic exchange between client and AP:
1. AP sends a random nonce (ANonce)
2. Client replies with a second nonce (SNonce) and a MIC derived from the PSK
3. AP validates, then sends the Group Temporal Key (GTK)
4. Client acknowledges, establishing an encrypted channel

This exchange can be captured in passive mode and later cracked if PSKs are weak or reused.

---

This write-up is part of a structured series of IOCs engineered for real-world application and layered triage analysis.

Addendum – Reconnaissance for BSSID (MAC) Acquisition
The attacker does not need to compromise a host or gain network access to spoof a Wi-Fi access point’s MAC address (BSSID). Instead, they passively gather this information from beacon frames that are openly broadcast by all wireless access points. These 802.11 management frames include both the SSID (network name) and the BSSID (MAC address of the AP radio interface), as well as encryption type, channel, and signal strength. Tools such as airodump-ng, Wireshark in monitor mode, or Kismet can capture this data in seconds. By analyzing these frames, the attacker learns everything needed to clone the legitimate network’s identity and configure an evil twin access point, all without sending a single packet or alerting the target network. This passive reconnaissance step makes Wi-Fi impersonation highly stealthy and accessible to low-profile attackers.




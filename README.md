# ADF-Project
PCAP Analyser

    The PCAP Analyser is a Python script designed to analyze PCAP files for detecting network attacks. It uses the Scapy library for packet manipulation and analysis, and the tkinter library for creating a graphical user interface (GUI) to interact with the tool.

Requirements:

    Python 3.x
    Scapy 2.x
    tkinter library

Installation:
    Install Python 3.x.
    Install Scapy and tkinter libraries using the following commands in the command prompt or terminal:
    pip install scapy
    pip install tkinter

Usage:

    Run the PCAP_Analyser.py script using the following command in the command prompt or terminal:

    python PCAP_Analyser.py

    The script will launch a graphical user interface where you can select the PCAP file you want to analyze using the "Select file" button.

    Once you have selected the PCAP file, you can choose which types of attacks you want to analyze using the checkboxes provided:

    SYN Flood Attack Detection
    SYN_RST Check
    DNS Spoofing Detection
    Man-in-the-middle Attack
    Click on the "Analyse" button to start the analysis.

    After the analysis is complete, the tool will display the results of the analysis on the GUI, as well as save the results in the log files located in the same directory as the script.

    Click on the "Return to Main Menu" button to return to the main menu and select another PCAP file to analyze.

Features:

    SYN Flood Attack Detection: This feature checks if the selected PCAP file has suspected SYN Flood attacks. It uses a threshold value to determine if a source IP address is launching a SYN Flood attack.

    SYN_RST Check: This feature checks if the selected PCAP file has TCP packets with both "SYN" and "RST" flags set at the same time.

    DNS Spoofing Detection: This feature checks if the selected PCAP file has DNS Spoofing attacks. It searches for DNS responses with incorrect IP addresses and DNS queries with no responses.

    Man-in-the-middle Attack: This feature checks if the selected PCAP file has Man-in-the-middle (MITM) attacks. It searches for ARP packets with multiple MAC addresses for a single IP address.

License:

    The PCAP Analyser is released under the MIT License. See the LICENSE file for more information.

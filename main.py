import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from scapy.layers.inet import IP, TCP
from scapy.all import rdpcap
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP

def open_pcap_file():
    global filename
    filename = filedialog.askopenfilename(initialdir="/", title="Select file",
                                          filetypes=(("PCAP files", "*.pcap"), ("all files", "*.*")))

def analyse():
    window.withdraw()
    root1 = tk.Tk()
    root1.title("PCAP Analyser")
    packets = rdpcap(filename)
    if option1_var.get()==1:
        SYN_flood_check(packets,root1)
    if option2_var.get()==1:
        SYN_RST_check(packets,root1)
    if option3_var.get()==1:
        dns_spoofing_detection(packets,root1)
    if option4_var.get()==1:
        man_in_the_middle_attack(packets,root1)

    loop = tk.Frame(root1)
    loop.pack()
    main_menu_button = tk.Button(loop, text="Return to Main Menu", command=window.deiconify)
    main_menu_button.pack()

def SYN_flood_check(packets,window):
    root1 = tk.Frame(window)
    root1.pack()
    root1.config(bd=4, relief="groove")
    # create a label and pack it
    label = tk.Label(root1, text="Checking if the PCAP file has suspected SYN Flood attacks please wait", wraplength=500, justify='left')
    label.pack(pady=10)
    syn_flood_flag = False
    progress_bar1 = ttk.Progressbar(root1, orient="horizontal", length=200, mode="determinate")
    progress_bar1.pack(pady=10)
    progress_bar1.start()

    for packet in packets:
        if TCP in packet and packet[TCP].flags & 0x02 and not packet[TCP].flags & 0x10:
            # Increment the SYN count for the source IP address
            src_ip = packet[IP].src
            syn_counts[src_ip] = syn_counts.get(src_ip, 0) + 1

    n = 100
    for i in range(n):
        progress1 = (i + 1) / n * 100  # calculate the progress percentage
        progress_bar1['value'] = progress1
        root1.update()  # update the GUI
    progress_bar1.stop()  # stop the progress bar
    progress_bar1.destroy()

    with open('SYN_flood_output.log', 'a') as file:
        for src_ip, count in syn_counts.items():
            if count > threshold:
                syn_flood_flag = True
                file.write(f'TCP SYN flood attack detected from source IP: {src_ip}')
                label1 = tk.Label(root1, text=f'TCP SYN flood attack detected from source IP: {src_ip}',fg='red',wraplength=500, justify='left')
                label1.pack(pady=10)
                print('TCP SYN flood attack detected from source IP:', src_ip)
        if not syn_flood_flag:
            file.write("[+] No suspicious SYN Flood attack detected")
            label2 = tk.Label(root1, text="[+] No suspicious SYN Flood attack detected",fg='green',wraplength=500, justify='left')
            label2.pack(pady=10)
            print("[+] No suspicious SYN Flood attack detected")

    label.config(text="SYN_flood Attack check complete! Check the 'SYN_flood_output.log' file for more detailed logs.",wraplength=500, justify='left')

def SYN_RST_check(packets, window):
    root1 = tk.Frame(window)
    root1.pack()
    root1.config(bd=4, relief="groove")
    label = tk.Label(root1, text="Checking if the PCAP file TCP packets with both 'SYN' and 'RST' flags set at the same time.",wraplength=500, justify='left')
    label.pack(pady=10)
    progress_bar1 = ttk.Progressbar(root1, orient="horizontal", length=200, mode="determinate")
    progress_bar1.pack(pady=10)
    progress_bar1.start()
    n = 50
    for i in range(n):
        progress1 = (i + 1) / n * 100  # calculate the progress percentage
        progress_bar1['value'] = progress1
        root1.update()  # update the GUI
    progress_bar1.stop()  # stop the progress bar
    progress_bar1.destroy()
    SYN_and_RST_flag = False
    with open('SYN_RST_Check_output.log', 'a') as file:
        for packet in packets:
            if TCP in packet:
                # Check if the SYN and RST flags are set
                if packet[TCP].flags & (0x02 | 0x04) == (0x02 | 0x04):
                    SYN_and_RST_flag = True
                    file.write(f"Packet with both SYN and RST flags detected:{packet.summary()}")
                    print("Packet with both SYN and RST flags detected:")
                    print(packet.summary())
        if not SYN_and_RST_flag:
            label2 = tk.Label(root1,
                              text="[+] No packets with both SYN and RST flag set are detected in the selected PCAP file", fg='green',
                              wraplength=500, justify='left')
            label2.pack(pady=10)
            file.write("[+] No packets with both SYN and RST flag set are detected in the selected PCAP file")
            print("[+] No packets with both SYN and RST flag set are detected in the selected PCAP file")
        else:
            label1 = tk.Label(root1,
                              text='Packet with both SYN and RST flags detected. Please check "SYN_RST_Check_output.log" file for more details ', fg='red',
                              wraplength=500, justify='left')
            label1.pack(pady=10)

def dns_spoofing_detection(packets, window):
    root1 = tk.Frame(window)
    root1.pack()
    root1.config(bd=4, relief="groove")
    label = tk.Label(root1,
                     text="Detecting if there is DNS Spoofing seen on the PCAP file",
                     wraplength=500, justify='left')
    label.pack(pady=10)
    progress_bar1 = ttk.Progressbar(root1, orient="horizontal", length=200, mode="determinate")
    progress_bar1.pack(pady=10)
    progress_bar1.start()
    n=50
    for i in range(n):
        progress1 = (i + 1) / n * 100  # calculate the progress percentage
        progress_bar1['value'] = progress1
        root1.update()  # update the GUI
    progress_bar1.stop()  # stop the progress bar
    progress_bar1.destroy()
    cache = {}
    detect_flag = False
    detect_count = 0
    with open('DNS_spoofing_output.log', 'a') as file:
        for pkt in packets:
            if pkt.haslayer(DNS) and pkt.haslayer(IP):
                dns = pkt[DNS]
                if dns.qr == 0: # DNS query
                    qname = dns.qd.qname.decode('utf-8')
                    qtype = dns.qd.qtype
                    qclass = dns.qd.qclass
                    dnsid = dns.id
                    srcip = pkt[IP].src
                    # Checking if the DNS response for the same query already exists in the cache
                    dns_cache = cache.get((dnsid, srcip))
                    if dns_cache:
                        response = dns_cache[0]
                        response_qtype = dns_cache[1]
                        response_ttl = dns_cache[2]

                        # Comparing the response IP address and TTL with the original query
                        if response_qtype == qtype and dns.an and dns.an.rdata != response and dns.an.ttl != response_ttl:
                            detect_flag = True
                            detect_count+=1
                            file.write(f"[!] DNS spoofing detected! {srcip} is spoofing {qname} with {dns.an.rdata}")
                            print(f"[!] DNS spoofing detected! {srcip} is spoofing {qname} with {dns.an.rdata}")
                    else:
                        # Adding the DNS response to the cache
                        if dns.an is None:
                            detect_flag = True
                            detect_count += 1
                            file.write(f"[!] DNS spoofing detected! {srcip} is spoofing {qname} with no answer records")
                            print(f"[!] DNS spoofing detected! {srcip} is spoofing {qname} with no answer records")
                        else:
                            response = dns.an.rdata
                            response_qtype = qtype
                            response_ttl = dns.an.ttl
                            cache[(dnsid, srcip)] = (response, response_qtype, response_ttl)

        if not detect_flag:
            label1 = tk.Label(root1,
                              text="[+] No DNS spoofing detected in the pcap file", fg='green',
                              wraplength=500, justify='left')
            label1.pack(pady=10)
            file.write("[+] No DNS spoofing detected in the pcap file.")
            print("[+] No DNS spoofing detected in the pcap file.")
        else:
            label2 = tk.Label(root1,
                              text=f"[!] There were {detect_count} dns_spoofed packets detected in this PCAP file. Please check 'DNS_spoofing_output.log' file for more details", fg='red',
                              wraplength=500, justify='left')
            label2.pack(pady=10)
            file.write(f"[!] There were {detect_count} dns_spoofed packets detected in this PCAP file.")
            print(f"[!] There were {detect_count} dns_spoofed packets detected in this PCAP file.")

def man_in_the_middle_attack(packets,window):
    root1 = tk.Frame(window)
    root1.pack()
    root1.config(bd=4, relief="groove")
    label = tk.Label(root1,
                     text="Detecting if there is MITM attack seen on the PCAP file",
                     wraplength=500, justify='left')
    label.pack(pady=10)
    progress_bar1 = ttk.Progressbar(root1, orient="horizontal", length=200, mode="determinate")
    progress_bar1.pack(pady=10)
    progress_bar1.start()
    n = 50
    for i in range(n):
        progress1 = (i + 1) / n * 100  # calculate the progress percentage
        progress_bar1['value'] = progress1
        root1.update()  # update the GUI
    progress_bar1.stop()  # stop the progress bar
    progress_bar1.destroy()
    mitm_flag = False
    with open('MITM_output.log', 'a') as file:
        for pkt in packets:
            if ARP in pkt:
                if pkt[ARP].op == 2: # ARP reply
                    if pkt[ARP].psrc != pkt[ARP].pdst:
                        mitm_flag = True
                        file.write(f"[!] Possible MITM Attack detected: {pkt[ARP].psrc} is pretending to be {pkt[ARP].pdst}")
                        print(f"[!] Possible MITM Attack detected: {pkt[ARP].psrc} is pretending to be {pkt[ARP].pdst}")
    if not mitm_flag:
        label1 = tk.Label(root1,
                          text="There is no MITM attack in the PCAP provided", fg='green',
                          wraplength=500, justify='left')
        label1.pack(pady=10)
    else:
        label2 = tk.Label(root1,
                          text="Possible MITM Attack detected. Please check 'MITM_output.log' for more details", fg='red',
                          wraplength=500, justify='left')
        label2.pack(pady=10)

threshold = 1000
syn_counts = {}
window = tk.Tk()
label = tk.Label(text="Welcome to PCAP Analyser", fg="red", bg="white",width=50, height=3, font=("Times New Roman", 20))
label.pack(side=tk.TOP)
label.config(bd=4, relief="groove")

frame1 = tk.Frame(window)
frame1.pack()
label1 = tk.Label(frame1, text="Please select the PCAP file you want to analyse")
label1.pack(side=tk.LEFT)
browse_button = tk.Button(frame1, text="Browse", command=open_pcap_file)
browse_button.pack(side=tk.LEFT)

frame2 = tk.Frame(window)
frame2.pack(anchor="w", padx=10)
options_label = tk.Label(frame2, text="Choose your options:", anchor="w", justify="left")
options_label.pack(anchor="w")

frame3 = tk.Frame(window)
frame3.pack(anchor="w", padx=10)
# Create the checkbox options using Checkbutton widgets
option1_var = tk.IntVar()
option1_checkbox = tk.Checkbutton(frame3, text="SYN_flood_check", variable=option1_var, anchor="w", justify="left")
option1_checkbox.pack(anchor="w")

option2_var = tk.IntVar()
option2_checkbox = tk.Checkbutton(frame3, text="SYN_RST_check", variable=option2_var, anchor="w", justify="left")
option2_checkbox.pack(anchor="w")

option3_var = tk.IntVar()
option3_checkbox = tk.Checkbutton(frame3, text="dns_spoofing_detection", variable=option3_var, anchor="w", justify="left")
option3_checkbox.pack(anchor="w")

option4_var = tk.IntVar()
option4_checkbox = tk.Checkbutton(frame3, text="man_in_the_middle_attack", variable=option4_var, anchor="w", justify="left")
option4_checkbox.pack(anchor="w")

analyse_button = tk.Button(window, text="Analyse", command=analyse)
analyse_button.pack()

window.mainloop()

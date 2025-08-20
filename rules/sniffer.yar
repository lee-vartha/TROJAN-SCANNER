rule sniffer {
    meta: 
        description = "Detects network sniffing activity"
        author = "Lee"
        date = "18-08-2025"
        version = "1.0"

    strings:
        $sniffing_tool = "tcpdump" nocase
        $sniffing_tool2 = "wireshark" nocase
        $sniffing_tool3 = "tshark" nocase
        $sniffing_tool4 = "snort" nocase
        $sniffing_tool5 = "ngrep" nocase
        $sniffing_tool6 = "pcap_open" nocase

    condition:
        any of ($sniffing_tool*) 
}
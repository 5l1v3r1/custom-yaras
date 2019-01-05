rule is_sniffing
{
    meta:
    description = "[+] Possible network sniffer"

    strings:
    $snf0 = "sniffer" nocase fullword
    $snf1 = "rpcap:////" nocase
    $snf2 = "wpcap.dll" nocase fullword
    $snf3 = "pcap_findalldevs" nocase
    $snf4 = "pcap_open" nocase
    $snf5 = "pcap_loop" nocase
    $snf6 = "pcap_compile" nocase
    $snf7 = "pcap_close" nocase

    condition:
    any of them
}

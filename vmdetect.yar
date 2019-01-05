rule vmdetection
{
    meta:
    description: "[+] VM detection check"

    strings:
    $v1 = "VIRTUAL HD" nocase
    $v2 = "VMWARE VIRTUAL IDE HARD DRIVE" nocase
    $v3 = "QEMU HARDDISK" nocase
    $v4 = "VBOX HARDDISK" nocase
    $v5 = "The Wireshark Network Analyzer" 
    $v6 = "C:\\sample.exe"
    $v7 = "C:\\windows\\system32\\sample_1.exe"
    $v8 = "Process Monitor - Sysinternals: www.sysinternals.com"
    $v9 = "File Monitor - Sysinternals: www.sysinternals.com"
    $v10 = "Registry Monitor - Sysinternals: www.sysinternals.com"

    condition:
    any of them
}

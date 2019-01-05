rule avcheck
{
    meta:
    description =  "[+] Possible Anti-AV methods in binary file"

    strings:
    $av0 = "McAfee" nocase
    $av1 = "Kaspersky" nocase
    $av2 = "Symantec" nocase
    $av3 = "BitDefender" nocase
    $av4 = "Microsoft" nocase
    $av5 = "Sophos AV" nocase
    $av6 = "ESET-NOD32" nocase
    $av7 = "Comodo" nocase
    $av8 = "FireEye" nocase
    $av9 = "Panda" nocase

    condition:
    2 of ($av*)
}

rule isbinary
{
    meta:
    description: "[+] Detection for executable files"
    
    strings:
    $a = "This program cannot be run in DOS mode"
    $b =  "MZ"

    condition:
    $a in (1024..filesize)
}

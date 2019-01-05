rule autorun
{
    meta:
    description = "[+] Possible worm/autorun file"

    strings:
    $w0 = "[autorun]"
    $w1 = "open="

    condition:
    all of them
}

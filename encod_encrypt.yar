rule is_encoding
{
    meta:
    description = "[+] Possible encryption/compression in file"

    strings:
    $enc0 = "deflate" fullword
    $enc1 = "Jean-loup Gailly"
    $enc2 = "inflate" fullword
    $enc3 = "Mark Adler"
    $enc4 = "OpenSSL" fullword
    $enc5 = "SSLeay" fullword
	$enc6 = "b64" nocase
	$enc7 = "decode" fullword
	$enc8 = "encode" fullword

    condition:
    any of them
}

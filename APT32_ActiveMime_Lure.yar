rule APT32_ActiveMime_Lure {
meta:
    filetype = "MIME entity"
    authors = "Ian Ahl and Nick Carr"
    date = "2017-03-02"
    description = "Detection of APT32 phishing lures. Targeted FEYE customers in 2016&2017"

strings:
    $a1 = "office_text" wide ascii
    $a2 = "schtasks / create / tn" wide ascii
    $a3 = "scrobj.dll" wide ascii
    $a4 = "new-object net.webcliente" wide ascii
    $a5 =  "GetUserName" wide ascii
    $a6 = "WSHnet.UserName" wide ascii
    $a7 = "WSHnet.UserName" wide ascii
    
condition:
    4 of them
}

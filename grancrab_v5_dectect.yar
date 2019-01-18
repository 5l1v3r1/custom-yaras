rule gandGrab_v5 {
 meta:
     description = "Yara Rule for gandCrab ransomware v5"
     author = "CSE CybSec Enterprise - Z-Lab"
     last_updated = "2018-10-01"
     tlp = "white"
     category = "informational"
strings:
      $a1 = "@hashbreaker Daniel J. Bernstein let's dance salsa <3"
      $a2 = "jopochlen"
      $a3 = "%X ahnlab http://memesmix.net/media/created/dd0doq.jpg"
      $b = {55 8B EC E8 00 00 00 00 3E 83 04 24 11 75 05 74 03}
      
 condition:
      1 of ($a*) and $b
}

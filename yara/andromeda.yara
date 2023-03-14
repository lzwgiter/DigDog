/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule andromeda {
   meta:
      description = "另补充yara - file andromeda.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "76c65d79ade16f9b461d38f7e2433ac66c0569b36988705383f4b9cb64635af3"
   strings:
      $s1 = "kernEl32.DLL" fullword ascii
      $s2 = "vbII.10-1802.4.exe" fullword wide
      $s3 = "55555555555555555555555555555555" ascii /* hex encoded string 'UUUUUUUUUUUUUUUU' */
      $s4 = "*\\AD:\\9877O889879\\gugu.vbp" fullword wide
      $s5 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
      $s6 = "kernEl32" fullword ascii
      $s7 = "ujnyhbtgvf" fullword wide
      $s8 = "dzstfdztfd" fullword wide
      $s9 = "elalehsytibbsw" fullword ascii
      $s10 = "ujnyhbtgv" fullword ascii
      $s11 = "wwwwwr" fullword ascii
      $s12 = "lokmpo" fullword ascii
      $s13 = "nSioXPW4" fullword wide
      $s14 = "jalajo" fullword ascii
      $s15 = "wwwwx\"\"wwwwwwww" fullword ascii
      $s16 = "wwwww\"\"/wwx" fullword ascii
      $s17 = "vbII.10-1802.4" fullword wide
      $s18 = "fNarEqwYE" fullword wide
      $s19 = "112555487898545498788789456QRROVUUPVWXXVOPWTRVWRWWWSRWQTXUPVPQPORUXVWOVWXWSOO112555487898545498788789456n+" fullword ascii
      $s20 = "wwwwr\"\"\"" fullword ascii
   condition:
      8 of them
}


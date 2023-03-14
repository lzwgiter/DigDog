/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule alvabrig {
   meta:
      description = "另补充yara - file alvabrig.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "93afdf161b4f0c6b1c9e32cadc4a0105d56d8ca61c7909d6aaa5c17722d76cb6"
   strings:
      $s1 = "laoz@symantec.com" fullword ascii
      $s2 = "sysw.tmp" fullword ascii
      $s3 = "sysp.tmp" fullword ascii
      $s4 = "sysk.tmp" fullword ascii
      $s5 = "1http://crl.usertrust.com/UTN-USERFirst-Object.crl0" fullword ascii
      $s6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\\" fullword ascii
      $s7 = "wincode.dat" fullword ascii
      $s8 = "kister.dat." fullword ascii
      $s9 = "osysk.dat" fullword ascii
      $s10 = "osysp.dat" fullword ascii
      $s11 = "pwrcode.dat" fullword ascii
      $s12 = "osysw.dat" fullword ascii
      $s13 = "\\krncode.dat" fullword wide
      $s14 = "laoz@symantec.com0 " fullword ascii
      $s15 = "laoz@symantec.com0" fullword ascii
      $s16 = "win32.dat" fullword ascii
      $s17 = "Comodo Time Stamping Signer0" fullword ascii
      $s18 = "shifld2.old" fullword ascii
      $s19 = "nsysp.ini" fullword ascii
      $s20 = "nsysw.ini" fullword ascii
   condition:
      8 of them
}


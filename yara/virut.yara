/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_virut {
   meta:
      description = "另补充yara - file virut.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "613f549be2a220547247ae5ebedfabfb85afd8fae56b783925b064556c024911"
   strings:
      $s1 = "ws2_32.dll" fullword ascii
      $s2 = "hijklmnpo" fullword ascii
      $s3 = "FGHIJKLM" fullword ascii
      $s4 = "RPNV -" fullword ascii
      $s5 = "RangCe " fullword ascii
      $s6 = "m\\Cuhy=n\\w" fullword ascii
      $s7 = "tOyky0v" fullword ascii
      $s8 = "vIxZzse" fullword ascii
      $s9 = "!%FpdP;gg" fullword ascii
      $s10 = "nczS*B%" fullword ascii
      $s11 = "ntEs<QP" fullword ascii
      $s12 = "THashs" fullword ascii
      $s13 = "SawH}W|" fullword ascii
      $s14 = "Zabcde8fg" fullword ascii
      $s15 = "netapi32.dll" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "DpHtk;9l" fullword ascii
      $s17 = "SPGh@](" fullword ascii
      $s18 = "bcdfg8hj^" fullword ascii
      $s19 = "Qfqrm@`" fullword ascii
      $s20 = "hZwd9+0" fullword ascii
   condition:
      8 of them
}


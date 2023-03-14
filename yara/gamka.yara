/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_gamka {
   meta:
      description = "另补充yara - file gamka.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "6bd4be224e527f33d66278c1fe77153b8275dbf700a3305e4ee4ca9deed33395"
   strings:
      $s1 = ".MSVCRTwr" fullword ascii /* base64 encoded string '1%BE<+' */
      $s2 = "-n*VisUC++ RALib" fullword ascii
      $s3 = "waqp!." fullword ascii
      $s4 = "dfPdoCompleteWait" fullword ascii
      $s5 = "InterlockedDecreme*Compo." fullword ascii
      $s6 = "mum (%d,Bm).F" fullword ascii
      $s7 = "s blocklinear" fullword ascii
      $s8 = "G -dd_RP" fullword ascii
      $s9 = "-t -X\\" fullword ascii
      $s10 = "ctoryFSZep9" fullword ascii
      $s11 = "oqkipm" fullword ascii
      $s12 = "\\.lhd`." fullword ascii
      $s13 = "StringWAGetL" fullword ascii
      $s14 = "7- Pa9" fullword ascii
      $s15 = "LhnkT^bd " fullword ascii
      $s16 = "Zefq^Y,{" fullword ascii
      $s17 = ".guq<$" fullword ascii
      $s18 = "NLDdHKGXNZLTW~" fullword ascii
      $s19 = "upOjnInfFi" fullword ascii
      $s20 = "ktyruhjdzhld}" fullword ascii
   condition:
      8 of them
}


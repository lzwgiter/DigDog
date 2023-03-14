/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule appetite {
   meta:
      description = "另补充yara - file appetite.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "541e0293ec77660546e30476c52e5af5a825ed2a090a3e45e2afc8f644e1e6da"
   strings:
      $s1 = "mfcn30.dll" fullword ascii
      $s2 = "MFCN30.DLL" fullword wide
      $s3 = "MFCNET Shared Library - Retail Version" fullword wide
      $s4 = "mfcn30.pdb" fullword ascii
      $s5 = "Copyright (C) Microsoft Corp. 1994-1995" fullword wide
      $s6 = "NPWj?X#" fullword ascii
      $s7 = "?%s=%s&%s=%ld&%s=%d&%s=%s&%s=%s&Ver=S%s" fullword ascii
      $s8 = "URPQQhh$" fullword ascii
      $s9 = "MFCNET" fullword wide
      $s10 = "9 9'9.959<9C9J9Q9Y9a9i9u9~9" fullword ascii
      $s11 = ":U:]:e:" fullword ascii
      $s12 = "8T8Y8u8" fullword ascii
      $s13 = "?%?=?R?W?]?x?}?" fullword ascii
      $s14 = ";0<7<?<" fullword ascii
      $s15 = "3(40464>4w4" fullword ascii
      $s16 = "9>9i9r9" fullword ascii
      $s17 = "7F8U8t8{8" fullword ascii
      $s18 = "3.2.000" fullword wide
      $s19 = "= =P=X=\\=d=h=p=t=|=" fullword ascii
      $s20 = "2.2.000" fullword wide
   condition:
      8 of them
}


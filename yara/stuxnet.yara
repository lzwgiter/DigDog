/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_stuxnet {
   meta:
      description = "另补充yara - file stuxnet.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "6c288878f9fd0bfc0bde65f3a6eca2632848b33f72e9e316a69a31aa4ec4da0b"
   strings:
      $s1 = "* g(C2" fullword ascii
      $s2 = "afso -" fullword ascii
      $s3 = "V5%A%a" fullword ascii
      $s4 = "DllGetClassObjectEx" fullword ascii
      $s5 = "w+fD+ !," fullword ascii
      $s6 = "CPlApplet" fullword ascii /* Goodware String - occured 15 times */
      $s7 = "~9tgkJ\\NF0" fullword ascii
      $s8 = "SwfsAy|" fullword ascii
      $s9 = "qBAAsfv" fullword ascii
      $s10 = "DiXjOv<" fullword ascii
      $s11 = "JoVhv]]c" fullword ascii
      $s12 = ":zfkmr~sW" fullword ascii
      $s13 = "cVcxJK^" fullword ascii
      $s14 = "GtRNd?N" fullword ascii
      $s15 = "-wJow}>1" fullword ascii
      $s16 = "#HumqAAm" fullword ascii
      $s17 = "wUfCc1<" fullword ascii
      $s18 = "uvg.lrBKP" fullword ascii
      $s19 = "OkDU:NF/" fullword ascii
      $s20 = "ZwQuerySection" fullword ascii
   condition:
      8 of them
}


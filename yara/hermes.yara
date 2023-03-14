/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_hermes {
   meta:
      description = "另补充yara - file hermes.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "2ca7c3b515863c5b51d415ce6e23dca11762b9bee5f860c4456937b3813d59ae"
   strings:
      $s1 = "C:\\Documents and Settings\\Roy\\My Documents\\VB Project\\Synon ERP\\Images\\magnifier16x16(8bit).ico" fullword ascii
      $s2 = "PB_DropAccept" fullword ascii
      $s3 = "PB_WindowID" fullword ascii
      $s4 = "rRLr\\^PaQB]" fullword ascii
      $s5 = "v[WGPzT\\\\T]" fullword ascii
      $s6 = "aRJY\\\\TF]hJocess" fullword ascii
      $s7 = "c^J@@SYsTTWcEx" fullword ascii
      $s8 = "rRLyZV@^PqQleNameA" fullword ascii
      $s9 = "xSlD-,,," fullword ascii
      $s10 = "LtuuuD(,,," fullword ascii
      $s11 = "gRKAXWaZJ]Yd" fullword ascii
      $s12 = "wYYJSp\\Te" fullword ascii
      $s13 = "DtuuuD(,,," fullword ascii
      $s14 = "vE]UAWe@W[]ssA" fullword ascii
      $s15 = "|PWIwZYWc" fullword ascii
      $s16 = "?DirectDrawCreateEx" fullword ascii
      $s17 = "vE]UAWs[T]y" fullword ascii
      $s18 = "pSlD-,,," fullword ascii
      $s19 = "bEQ@PbG][]KsMemory" fullword ascii
      $s20 = "{CmZXSEdQ]O" fullword ascii
   condition:
      8 of them
}


/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_logsnif {
   meta:
      description = "另补充yara - file logsnif.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "0f5574c4e531f24211440b66043e0416131fc0852f4e99ae71eb2fa557ff6e7d"
   strings:
      $s1 = "o=!dbv." fullword ascii
      $s2 = "dAu=)tMw" fullword ascii
      $s3 = "%eovG2" fullword ascii
      $s4 = "0xyoQh" fullword ascii
      $s5 = "&8V;T." fullword ascii
      $s6 = "Ho9,hI}" fullword ascii
      $s7 = ">Ch_7:O" fullword ascii
      $s8 = "ao@}~?yp" fullword ascii
      $s9 = "Pc~bxY" fullword ascii
      $s10 = "Rwc^UD/!" fullword ascii
      $s11 = "{?EIOHr" fullword ascii
      $s12 = "&dqz2," fullword ascii
      $s13 = "%!4A5)" fullword ascii
      $s14 = "/<6IEe" fullword ascii
      $s15 = "{7`N;W" fullword ascii
      $s16 = ">c|4AIT" fullword ascii
      $s17 = "Xgw/[F" fullword ascii
      $s18 = "6UCO)u3" fullword ascii
      $s19 = "]vq;2!" fullword ascii
      $s20 = "}QjVE<" fullword ascii
   condition:
      8 of them
}


/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_trafog {
   meta:
      description = "另补充yara - file trafog.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "5d29bd5297eea5837e5a3f2bd9d3bc1020ce4c7d89016ac21835da8c4cafdeca"
   strings:
      $s1 = "Q0u9{OnyXS|5uexect" fullword ascii
      $s2 = "\\fJjpQQ44zfl:\\a5" fullword ascii
      $s3 = "C:\\Project" fullword ascii
      $s4 = "7:sowJuU3p:\\vUg" fullword ascii
      $s5 = "Y|JSaGQRfEdi:\\IT]kUpgfQbivW" fullword ascii
      $s6 = "kTfe[6GM:\\jN" fullword ascii
      $s7 = "JlkPFcLJ:\\_xWR9u>{" fullword ascii
      $s8 = "YooO}jvFHH7<<<9Wd:\\^Y" fullword ascii
      $s9 = "hWxeR~Smqo4W[gm5Xyq:\\TS9ydJ_Z" fullword ascii
      $s10 = "Fz_anaeJ}orDB28|fkTx:\\a=r" fullword ascii
      $s11 = "NvE.PSh;NSxCMQ^~R<|g[j|Y" fullword ascii
      $s12 = "QFFQ.NXn[Ytxa" fullword ascii
      $s13 = "udLl\\PshW:Nn[sC>" fullword ascii
      $s14 = "n3dgD:KX:;}A>e8eR~dlLh|y_nMQ" fullword ascii
      $s15 = "ctoG;tftp{\\" fullword ascii
      $s16 = "livJspYuyvyW" fullword ascii
      $s17 = "Qmpzjo6^tIrc" fullword ascii
      $s18 = "wzyCl7O:kSPY}u@SWh" fullword ascii
      $s19 = "K[NoOnUzNLsPyA`U" fullword ascii
      $s20 = "tdARkYVfWEyo}_]iMUtLZSfm]USat" fullword ascii
   condition:
      8 of them
}


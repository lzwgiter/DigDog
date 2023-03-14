/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_lolyda {
   meta:
      description = "另补充yara - file lolyda.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "62f1707394325b5c3ac09df8e362b9a0710fbc956b3327f419063e24182c1e5b"
   strings:
      $s1 = "\\TEMP%c:\\Recy" fullword ascii
      $s2 = "L32.dll" fullword ascii
      $s3 = "GetTemp" fullword ascii
      $s4 = "JX3Client.exeksuser" fullword ascii
      $s5 = "d\\%d.tmp" fullword ascii
      $s6 = "configm" fullword ascii
      $s7 = "?cmD\\pkBmngpD" fullword ascii
      $s8 = "/,/5.:0^*" fullword ascii /* hex encoded string 'P' */
      $s9 = "k5-o- TTRVFHAWCO=IQ" fullword ascii
      $s10 = "ECYCLER" fullword ascii
      $s11 = "te cryptsvc" fullword ascii
      $s12 = "- I)PI" fullword ascii
      $s13 = "pahpnt" fullword ascii
      $s14 = "CreateToolhelp3" fullword ascii
      $s15 = "kingsoft\\\\zhcno" fullword ascii
      $s16 = "!art=*isab-d=`" fullword ascii
      $s17 = "SOFTWARE\\(" fullword ascii
      $s18 = "Z^[gpol]_\\d" fullword ascii
      $s19 = "<_lgoYobBbt^g_k\\G^plpp" fullword ascii
      $s20 = "cickCoun~!" fullword ascii
   condition:
      8 of them
}


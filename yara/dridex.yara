/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_dridex {
   meta:
      description = "另补充yara - file dridex.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "fa0d7cfb1ae1d770ce6202a574d23a878354fadfce4101cad53f062dd9d77f03"
   strings:
      $s1 = "Crypt32.dll" fullword ascii
      $s2 = "SensorsApi.dll" fullword wide
      $s3 = "snxhk.dll" fullword ascii
      $s4 = "ffffff." fullword ascii /* reversed goodware string '.ffffff' */
      $s5 = "GetVolumePathNameA" fullword ascii
      $s6 = "WriteHitLogging" fullword ascii
      $s7 = "putmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedve" ascii
      $s8 = "jmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedvepu" ascii
      $s9 = "medveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveput" ascii
      $s10 = "medveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveput" ascii
      $s11 = "medveputmedveputmedveput" fullword ascii
      $s12 = "putmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveput" fullword ascii
      $s13 = "medveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveput" ascii
      $s14 = "medveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveput" fullword ascii
      $s15 = "medveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveput" ascii
      $s16 = "tmedveputmedveputmedveputmedveputmedveputmedveput" fullword ascii
      $s17 = "jmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedvepu" ascii
      $s18 = "medveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveput" ascii
      $s19 = "medveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveputmedveput" ascii
      $s20 = "medveputmedveputmedveputmedveputmedveput" fullword ascii
   condition:
      8 of them
}


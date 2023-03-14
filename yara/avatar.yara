/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_avatar {
   meta:
      description = "另补充yara - file avatar.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "d1a8d74aadb10bff4bfda144e68db3e087ec4fee82cd22df22839fd5435d0d37"
   strings:
      $s1 = " %suxtheme.dll;%scryptbase.dll" fullword wide
      $s2 = "ComSpec" fullword ascii
      $s3 = "\\KernelObjects\\%SCondition`0000000000000" fullword wide
      $s4 = "263;3@3\\3" fullword ascii /* hex encoded string '&33' */
      $s5 = "\\Hu:\\S" fullword ascii
      $s6 = "YcoM{cp" fullword ascii
      $s7 = "ScE0.nhv" fullword ascii
      $s8 = "gKYWMO<+k" fullword ascii
      $s9 = "nRelyFt" fullword ascii
      $s10 = "(Otfokf0" fullword ascii
      $s11 = "fyGDu4e" fullword ascii
      $s12 = "vKcI?I" fullword ascii
      $s13 = "goSjRIe" fullword ascii
      $s14 = "TIeWJ8oV" fullword ascii
      $s15 = "]plorjMbs" fullword ascii
      $s16 = "`SjLa5Dt" fullword ascii
      $s17 = "rere ]-" fullword ascii
      $s18 = "erex(Auc%r" fullword ascii
      $s19 = "Global\\{%s}`000000000000000000000000000000009" fullword ascii
      $s20 = "Global\\{%s}`000000000000000000000000000000002" fullword ascii
   condition:
      8 of them
}


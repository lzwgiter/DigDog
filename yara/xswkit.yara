/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_xswkit {
   meta:
      description = "另补充yara - file xswkit.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "34f9e77c56549fa25b02ae97891054b963b4bc9e32971b65cc6f203e8a2792f1"
   strings:
      $s1 = "Replugged.exe" fullword wide
      $s2 = "RecirculatedPassives" fullword ascii
      $s3 = "PortentsRecommissioning" fullword ascii
      $s4 = "MiningPassports" fullword ascii
      $s5 = "PrivilegedReadies" fullword ascii
      $s6 = "RecapturePoisons" fullword ascii
      $s7 = "ProxyPortions" fullword ascii
      $s8 = "RabatPostal" fullword ascii
      $s9 = "NotationalOperable" fullword ascii
      $s10 = "RipostePillar" fullword ascii
      $s11 = "RetitlingRescanned" fullword ascii
      $s12 = "RiftPollen" fullword ascii
      $s13 = "MotivePostmodernist" fullword ascii
      $s14 = "RedbloodedPerspective" fullword ascii
      $s15 = "PsychologyPerceives" fullword ascii
      $s16 = "ParallelogramsScience" fullword ascii
      $s17 = "OverestimatesMinicomputers" fullword ascii
      $s18 = "AdjustTokenGroups" fullword ascii
      $s19 = "RerunningRipple" fullword ascii
      $s20 = "ProofreadersPossum" fullword ascii
   condition:
      8 of them
}


/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_cridex {
   meta:
      description = "另补充yara - file cridex.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "046a7fac35a29f66e37193a2048f6a324754df131bad07c21f87fc814d7763f5"
   strings:
      $s1 = "MediaType.Description.bak" fullword wide
      $s2 = "Gsystem32\\cGcript.Gxe" fullword wide
      $s3 = "RunDll.Win9x" fullword wide
      $s4 = "Shell.Play9Software\\Microsoft\\Multimedia\\ActiveMovie\\File Extensions" fullword wide
      $s5 = "RunDll.NT" fullword wide
      $s6 = "zegOpenKeyExW" fullword ascii
      $s7 = "MediaType.Open.bak" fullword wide
      $s8 = "MIME.CLSID.bak" fullword wide
      $s9 = "Extension.MediaType.bak" fullword wide
      $s10 = "Extension.MIME.bak" fullword wide
      $s11 = "wsvcPr.dFj" fullword ascii
      $s12 = "MediaType.Verb.bak" fullword wide
      $s13 = "MediaType.Icon.bak" fullword wide
      $s14 = "MediaType.MediaType.bak" fullword wide
      $s15 = "MediaType.Play.bak" fullword wide
      $s16 = "Shortcut.Parameters" fullword wide
      $s17 = "OCX.ocx" fullword wide
      $s18 = "MediaType.MediaType" fullword wide
      $s19 = "PUSHBUTTON" fullword ascii
      $s20 = "ActiveMovie Control" fullword wide
   condition:
      8 of them
}


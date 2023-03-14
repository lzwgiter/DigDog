/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_murofet {
   meta:
      description = "另补充yara - file murofet.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "47bb201c4dcabbf7afe5888aad003de26f41c4f3e261140ce808309e4db0f0f9"
   strings:
      $x1 = "C:\\WINDOWS\\system32\\shdocvw.dll" fullword ascii
      $s2 = "Netapi32.dll" fullword ascii
      $s3 = "Win.exe" fullword wide
      $s4 = "smtpserver" fullword wide
      $s5 = "B*\\AD:\\Code\\Explorer\\Explorer.vbp" fullword wide
      $s6 = "http://schemas.microsoft.com/cdo/configuration/" fullword wide
      $s7 = "sendpassword" fullword wide
      $s8 = "smtpserverport" fullword wide
      $s9 = "smtpconnectiontimeout" fullword wide
      $s10 = "explorer.exe, " fullword wide
      $s11 = "smtpusessl" fullword wide
      $s12 = "</xCommand>" fullword wide
      $s13 = "<xCommand" fullword wide
      $s14 = "smtpauthenticate" fullword wide
      $s15 = "sendusername" fullword wide
      $s16 = "<Download>" fullword wide
      $s17 = "</Download>" fullword wide
      $s18 = "urlmon" fullword ascii
      $s19 = "URLDownloadToFileA" fullword ascii
      $s20 = "9ShellIE" fullword ascii
   condition:
      4 of them
}


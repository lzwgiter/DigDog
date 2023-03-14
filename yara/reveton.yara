/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_reveton {
   meta:
      description = "另补充yara - file reveton.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "a8c0e4919ad7d56813fa2d5c572382801763b3ce320fc8a8f75118ea12de212c"
   strings:
      $s1 = "globalDoc.execCommand(\"AutoDetect\");" fullword ascii
      $s2 = "range.execCommand(select.id.substring(3), false," fullword ascii
      $s3 = "range.execCommand(FontNameCommand, false, txtFontName.value);" fullword ascii
      $s4 = "range.execCommand(cmdCreateLink, false, txtURL.value);" fullword ascii
      $s5 = "grngMaster.execCommand(cmdDelete);" fullword ascii
      $s6 = "grngMaster.execCommand(cmdInsertImage, false, idstr);" fullword ascii
      $s7 = "range.execCommand(checkbox.value, false);" fullword ascii
      $s8 = "range.execCommand(cmdUnlink, false);" fullword ascii
      $s9 = "range.execCommand(cmdForeColor, false," fullword ascii
      $s10 = "var fUseExecCommand = true;" fullword ascii
      $s11 = "fUseExecCommand = false;" fullword ascii
      $s12 = "if ( fUseExecCommand )" fullword ascii
      $s13 = "google.combluegoogle.com" fullword ascii
      $s14 = "http://google.com" fullword ascii
      $s15 = "execCommand(cmdBold, false);" fullword ascii
      $s16 = "WZW.dll" fullword ascii
      $s17 = "execCommand(cmdItalic, false);" fullword ascii
      $s18 = "var strSlashProts = \" file:ftp:gopher:http:https:\";" fullword ascii
      $s19 = "txtURL.value = strProtocolSel + strTempURL;" fullword ascii
      $s20 = "httpgoogle.comObjectONLZmT,LOVl$]$5fx`M!kdJLc#{_~ >B< B8ZSB2Nn" fullword wide
   condition:
      8 of them
}


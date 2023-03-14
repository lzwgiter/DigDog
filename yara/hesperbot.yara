/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule hesperbot {
   meta:
      description = "另补充yara - file hesperbot.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "86a678b8fad701a231bb9562a8719095d44a02cf888fbf2e1a86d42b43e27fe9"
   strings:
      $s1 = "MFC42.DLL" fullword ascii
      $s2 = "iclllllllll" fullword ascii
      $s3 = "cran'Passe " fullword wide
      $s4 = "ques OLE sont de la bonne version." fullword wide
      $s5 = "/Passe au volet de fen" fullword wide
      $s6 = "tre de document suivante)Passe " fullword wide
      $s7 = "Z version 1.0" fullword wide
      $s8 = "CChildFrame" fullword ascii
      $s9 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
      $s10 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii
      $s11 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
      $s12 = "KPGFVZY" fullword ascii
      $s13 = " dans le registre du syst" fullword wide
      $s14 = "rifiez que les biblioth" fullword wide
      $s15 = "lectionne le document entier" fullword wide
      $s16 = "cifique par un texte diff" fullword wide
      $s17 = "SPy5M!" fullword ascii
      $s18 = "8 -|T(" fullword ascii
      $s19 = "Kx+ j.5K" fullword ascii
      $s20 = "BUBZAy1" fullword ascii
   condition:
      8 of them
}


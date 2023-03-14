/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-08
   Identifier: new
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule sazoora {
   meta:
      description = "new - file sazoora.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-08"
      hash1 = "6796096071d1d89bdf4d62d136acdd043b176f47b8f8969d6f32f1959e8980c7"
   strings:
      $s1 = "MFC42.DLL" fullword ascii
      $s2 = "http://www.microsoft.com/visualc/" fullword ascii
      $s3 = "C:\\windows\\explorer.exe..\\" fullword ascii
      $s4 = "che ou commande courante" fullword wide
      $s5 = "A FAIRE: Disposez la barre de dialogue " fullword wide
      $s6 = "TODO: layout dialog bar" fullword wide
      $s7 = "cran'Passe " fullword wide
      $s8 = "ques OLE sont de la bonne version." fullword wide
      $s9 = "/Passe au volet de fen" fullword wide
      $s10 = "S0 version 1.0" fullword wide
      $s11 = "tre de document suivante)Passe " fullword wide
      $s12 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
      $s13 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii
      $s14 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
      $s15 = "rifiez que les biblioth" fullword wide
      $s16 = "lectionne le document entier" fullword wide
      $s17 = "cifique par un texte diff" fullword wide
      $s18 = "Cwegewgwgme" fullword ascii
      $s19 = "wegweg" fullword ascii
      $s20 = "JJJy111" fullword ascii
   condition:
      8 of them
}


/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule blocrypt {
   meta:
      description = "另补充yara - file blocrypt.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "71905f51226e9e1436776a3c2445a241550febf8c46d896f22d60afb73bb00de"
   strings:
      $s1 = "http://microsoft.com" fullword ascii
      $s2 = "Colorado Time Zone,Nutcracker in Colorado - coloradoballet.org" fullword wide
      $s3 = "ntcrypt32.tpl" fullword ascii
      $s4 = "oSeDebugPrivilege" fullword wide
      $s5 = "im fed up with cleaning" fullword ascii
      $s6 = "fcfd1af84e4d96ab5c1bda0d20a6c317824155478776d0475b08b0a3fce7587086514b22c8842d9f022f5b5a75a1457d1aa1bb4ca363c74ac80c6967aa6e9b1d" ascii
      $s7 = "fcfd1af84e4d96ab5c1bda0d20a6c317824155478776d0475b08b0a3fce7587086514b22c8842d9f022f5b5a75a1457d1aa1bb4ca363c74ac80c6967aa6e9b1d" ascii
      $s8 = "delete" fullword ascii /* Goodware String - occured 149 times */
      $s9 = "3 3-3k3" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "edfe13ee091d" ascii
      $s11 = "edfe13ee091f" ascii
      $s12 = "=d>m>y>" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "edfe13ee0919" ascii
      $s14 = "G PSSh" fullword ascii /* Goodware String - occured 1 times */
      $s15 = ">H>]>m>" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "?3?O?g?" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "2f19e1222497a6bdf8aa05de2903018f2fdd4259bbffcf01d5733465" ascii
      $s18 = ": :$:(:,:0:@:D:H:L:P:T:X:\\:`:d:h:l:p:t:x:|:" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "8ad32cdc7d6db08f250afe0731bbdf0b8b537d48bd77dd52422489" wide
      $s20 = "edfe13ee091e" ascii
   condition:
      8 of them
}


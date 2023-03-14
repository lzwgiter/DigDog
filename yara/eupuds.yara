/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_eupuds {
   meta:
      description = "另补充yara - file eupuds.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "7ac7bff9fb92fe2a74f695994381bf30719241a1387fe17bf495c419c31f14cb"
   strings:
      $s1 = "L7ADVAPI32.dll" fullword ascii
      $s2 = "5 5$5(575" fullword ascii /* hex encoded string 'UUu' */
      $s3 = "235{5^6.8" fullword ascii /* hex encoded string '#Uh' */
      $s4 = "8H:L:P:T:X:\\:`:d:h:l:p:t:x:|:" fullword ascii
      $s5 = ": :$:(:,:0:4:8:<:@:D:H:L:P:T:X:\\:`:d:<;@;X=\\=`=d=h=l=p=t=x=|=" fullword ascii
      $s6 = "S:\\2c}" fullword ascii
      $s7 = "zVSpy_" fullword ascii
      $s8 = "T /sN#M" fullword ascii
      $s9 = "76<?" fullword ascii /* hex encoded string 'v' */
      $s10 = "hgeofn" fullword ascii
      $s11 = "\\.LDi;" fullword ascii
      $s12 = "OlaLJ>>*9m>" fullword ascii
      $s13 = "uN0tFVN0w\\&" fullword ascii
      $s14 = "luYzx`h%" fullword ascii
      $s15 = "qwvs,e{" fullword ascii
      $s16 = "fyMB6qT" fullword ascii
      $s17 = "AbqE(\"" fullword ascii
      $s18 = "fatK([c" fullword ascii
      $s19 = "$dcqa=i@" fullword ascii
      $s20 = "4$4(4,444L4\\4`4p4t4|4" fullword ascii /* Goodware String - occured 1 times */
   condition:
      8 of them
}


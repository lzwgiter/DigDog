/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule neverquest {
   meta:
      description = "另补充yara - file neverquest.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "90f35605148bd15e92852af7007e09c13a7c4f2ed308e7e604d0a9a7d526d328"
   strings:
      $s1 = "sbvhdlhhd.dll" fullword ascii
      $s2 = "C:\\csegrggr\\gremsnhlhng\\tjrsefhjrege\\jewhbghjm32.pdb" fullword ascii
      $s3 = "BBoUR.iNy=" fullword ascii
      $s4 = "NNGyTy9" fullword ascii
      $s5 = "B* gB.I]ZLvTk" fullword ascii
      $s6 = "ufkjjk" fullword ascii
      $s7 = "SGewZa " fullword ascii
      $s8 = "VR.imZ\\vdk" fullword ascii
      $s9 = "V2MJmZ\\vdk" fullword ascii
      $s10 = "N~v5RnveZs_Z" fullword ascii
      $s11 = "GQp^|NZ=vEky={B#oV3.J" fullword ascii
      $s12 = "dlxFhIO" fullword ascii
      $s13 = "ZvYEky=" fullword ascii
      $s14 = "+JxHg(Am" fullword ascii
      $s15 = "YZdL!]@" fullword ascii
      $s16 = "Ir.Zov" fullword ascii
      $s17 = "m{nSorc.T^" fullword ascii
      $s18 = "@pEKIcf>" fullword ascii
      $s19 = "FuxGrX[" fullword ascii
      $s20 = "BzWoR27qdu!B" fullword ascii
   condition:
      8 of them
}


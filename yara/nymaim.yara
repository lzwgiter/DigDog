/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_nymaim {
   meta:
      description = "另补充yara - file nymaim.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "d9be07e6f40a8c77cd2c36d979e6079ce5756b7923f1040cad095744fc402031"
   strings:
      $s1 = "Iojyajpgqjyir Wwg.exe" fullword wide
      $s2 = "xmLi,Xf#g.sCr" fullword ascii
      $s3 = "GdipGetLogFontW" fullword ascii
      $s4 = "* U[kU2*J]WJp0xhGG-d)V" fullword ascii
      $s5 = "+!c:\\yL\\Du,%VlPi2<EG%8YZ_Eu*" fullword ascii
      $s6 = "iGjrg:\\gJ.-L6!" fullword ascii
      $s7 = "GdipGetRegionScansCount" fullword ascii
      $s8 = "^N$tpbR!|%tBtD<ftPW' Om" fullword ascii
      $s9 = "~dMircg|*1qz^&U\">6EA" fullword ascii
      $s10 = "CM_Get_DevNode_Registry_PropertyA" fullword ascii
      $s11 = "CM_Get_DevNode_Registry_Property_ExA" fullword ascii
      $s12 = "CM_Get_Device_ID_ExA" fullword ascii
      $s13 = "GdipGetPathFillMode" fullword ascii
      $s14 = "* MT %tx)u=PL_:mi" fullword ascii
      $s15 = "GdipGetPathData" fullword ascii
      $s16 = "GdipGetRegionHRgn" fullword ascii
      $s17 = "GdipGetPointCount" fullword ascii
      $s18 = "GdipGetMatrixElements" fullword ascii
      $s19 = "GdipGetRegionBounds" fullword ascii
      $s20 = "GdipGetMetafileHeaderFromStream" fullword ascii
   condition:
      8 of them
}


/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule ramnit2016 {
   meta:
      description = "另补充yara - file ramnit2016.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "e9cd4d4affcb97b298fafe52a1a7f8e054e0ea4ac9ce0f9dc0bc4a199a10e30f"
   strings:
      $s1 = "Scholar vault unencrypted Content become " fullword ascii
      $s2 = "E:\\spooky\\surface\\Eq\\policing\\Onei.pdb" fullword ascii
      $s3 = "Migration disagreement coprocessors messaging " fullword ascii
      $s4 = "ExecuteScalar " fullword ascii
      $s5 = "WM_MOVE Called - New Positition = (%d,%d)" fullword ascii
      $s6 = "midst bilabial spawns bear unsightly " fullword ascii
      $s7 = "GetInterfaceInfo failed with error: %d" fullword ascii
      $s8 = "QLogic dropped " fullword ascii
      $s9 = "VJE Text Files (*.txt)" fullword wide
      $s10 = "WX Text Files (*.txt)" fullword wide
      $s11 = "box normalization hosts quasi " fullword ascii
      $s12 = "prime forward windshield " fullword ascii
      $s13 = "cccugcccgc*cc:\"|cc{" fullword ascii
      $s14 = "miracles Downloads reach workday " fullword ascii
      $s15 = "Typing ISomeInterfaces Account 0x0000 " fullword ascii
      $s16 = "http://ocsp.comodoca.com0$" fullword ascii
      $s17 = "Listen failed: %u" fullword ascii
      $s18 = "bind failed: %u" fullword ascii
      $s19 = "Vmain.ico" fullword wide
      $s20 = "Export completed." fullword wide
   condition:
      8 of them
}


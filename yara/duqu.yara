/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_duqu {
   meta:
      description = "另补充yara - file duqu.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "f2b631fcdf83b928661a7e09dd11fa640251a4850ff570436f3b16abef0fad10"
   strings:
      $s1 = "\\SystemRoot\\System32\\hal.dll" fullword wide
      $s2 = "jminet7.sys" fullword wide
      $s3 = "ntkrnlpa.exe" fullword ascii
      $s4 = " 2001-2006 JMicron Technology Corporation. All rights reserved." fullword wide
      $s5 = "JMicron Technology Corporation" fullword wide
      $s6 = "\\DosDevices\\GpdDev" fullword wide
      $s7 = "92:B:V:\\:h:s:|:" fullword ascii
      $s8 = "JMicron Volume Snapshot Driver" fullword wide
      $s9 = "ZwQuerySystemInformation" fullword wide
      $s10 = "RSSSSSQ" fullword ascii
      $s11 = "PADDINGXXPAD" fullword ascii
      $s12 = "2.1.0.14" fullword wide
      $s13 = "\\Device\\Gpd1" fullword wide
      $s14 = "\\Device\\Gpd0" fullword wide
      $s15 = "KeInitializeMutex" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "IoInitializeRemoveLockEx" fullword ascii
      $s17 = "InternalCopyright" fullword wide
      $s18 = "0SUVW3" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "7%8P8}8" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "IoFreeWorkItem" fullword ascii /* Goodware String - occured 1 times */
   condition:
      8 of them
}


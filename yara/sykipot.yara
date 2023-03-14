/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule _home_float__________yara_sykipot {
   meta:
      description = "另补充yara - file sykipot.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "d45a7b517507c78fe3aeca26d9b8aee20e2480b12f47d71f924142339813f5a7"
   strings:
      $s1 = "C:\\Program Files(x86)\\ActivIdentity\\ActivClient\\acpkcs201.dll" fullword ascii
      $s2 = "C:\\Program Files\\ActivIdentity\\ActivClient\\acpkcs201.dll" fullword ascii
      $s3 = "MSVCP60.dll" fullword ascii
      $s4 = "GetProcessMemoryInfo Error: %d" fullword ascii
      $s5 = "GetProcessTimes Error: %d" fullword ascii
      $s6 = "MSVCIRT.dll" fullword ascii
      $s7 = "wship4.dll" fullword wide
      $s8 = "ServerDll.dll" fullword ascii
      $s9 = "https://www.happybehere.com/asp/kys_allow_get.asp?name=" fullword ascii
      $s10 = "https://www.happybehere.com/asp/kys_allow_get.asp?name=getkys.dat" fullword ascii
      $s11 = "EXPLORER.EXE" fullword ascii
      $s12 = "outlook.exe" fullword ascii
      $s13 = "firefox.exe" fullword ascii
      $s14 = "taskmost.exe" fullword ascii
      $s15 = "www.happybehere.com" fullword ascii
      $s16 = "OpenProcessToken Error: %d" fullword ascii
      $s17 = "\\svchost.exe" fullword ascii
      $s18 = "\\acpkcs201.dll" fullword ascii
      $s19 = "MFC42.DLL" fullword ascii
      $s20 = "dmm.exe" fullword ascii
   condition:
      8 of them
}


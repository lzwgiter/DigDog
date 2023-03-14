/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule lecpetex {
   meta:
      description = "另补充yara - file lecpetex.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "976e018d376fa896f766f9be66ad15e1e662d6e723042c1a29e1509cc1f3aad3"
   strings:
      $x1 = "select name, encrypted_value from cookies where host_key like '.facebook.com'" fullword ascii
      $s2 = "select name, value from cookies where host_key like '.facebook.com'" fullword ascii
      $s3 = "upload.facebook.com" fullword ascii
      $s4 = "User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/19.77.34.5 Safari/537.1" fullword ascii
      $s5 = "graph.facebook.com" fullword ascii
      $s6 = "www.facebook.com" fullword ascii
      $s7 = "C:\\Temp:list1" fullword ascii
      $s8 = "https://www.facebook.com/%s\">" fullword ascii
      $s9 = "User-Agent: Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobil" ascii
      $s10 = "User-Agent: Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobil" ascii
      $s11 = "delete from cookies where host_key like '%facebook%';" fullword ascii
      $s12 = "m.facebook.com" fullword ascii
      $s13 = "User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36" fullword ascii
      $s14 = "User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.13 (KHTML, like Gecko) Chrome/24.0.1290.1 Safari/537.13" fullword ascii
      $s15 = "User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.90 Safari/537.36" fullword ascii
      $s16 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3" fullword ascii
      $s17 = "User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36" fullword ascii
      $s18 = "User-Agent: Mozilla/5.0 (Windows NT 6.0) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.36 Safari/536.5" fullword ascii
      $s19 = "User-Agent: Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3" fullword ascii
      $s20 = "facebook.com/" fullword ascii
   condition:
      1 of ($x*) and 4 of them
}


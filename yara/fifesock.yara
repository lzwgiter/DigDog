/*
   YARA Rule Set
   Author: QYDD
   Date: 2020-05-04
   Identifier: 另补充yara
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */
rule fifesock {
   meta:
      description = "另补充yara - file fifesock.exe"
      author = "QYDD"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-04"
      hash1 = "11a3594612218e0018a94cdd40b12a22cf99809e4de0d1f48a1db9f5908eab97"
   strings:
      $x1 = "https://www.blogger.com/loginz?d=http%3A%2F%2Fwww.blogger.com%2Fhome&a=ALL&service=blogger&naui=8&fpui=2&skipvpage=true&rm=false" ascii
      $x2 = "https://www.blogger.com/loginz?d=http%3A%2F%2Fwww.blogger.com%2Fsignup.g&a=ALL&service=blogger&naui=8&fpui=2&skipvpage=true&rm=f" ascii
      $x3 = "https://www.blogger.com/loginz?d=http%3A%2F%2Fwww.blogger.com%2Fsignup.g&a=ALL&service=blogger&naui=8&fpui=2&skipvpage=true&rm=f" ascii
      $x4 = "https://www.google.com/accounts/ServiceLogin?service=blogger&continue=https://www.blogger.com/loginz?d=http://www.blogger.com/ho" ascii
      $x5 = "https://www.google.com/accounts/ServiceLogin?service=blogger&continue=https://www.blogger.com/loginz?d=http://www.blogger.com/ho" ascii
      $x6 = "https://www.google.com/accounts/CreateServiceAccount?continue=https://www.blogger.com/loginz?d=http://www.blogger.com/home?pli=1" ascii
      $x7 = "https://www.google.com/accounts/CreateServiceAccount?continue=https://www.blogger.com/loginz?d=http://www.blogger.com/home?pli=1" ascii
      $x8 = "https://www.blogger.com/loginz?d=http://www.blogger.com/home?pli=1" fullword ascii
      $x9 = "[BLOGSPOT] CreaaAAAAted blog %s.blogspot.com, getting template page!" fullword ascii
      $x10 = "https://www.google.com/accounts/ServiceLoginAuth" fullword ascii
      $s11 = "[BLOGSPOT] Decoded HTML template" fullword ascii
      $s12 = "[BLOGSPOT] SUCCESSFULLY CREATED BLOG: http://%s.blogspot.com" fullword ascii
      $s13 = "[BLOGSPOT] Found blogger.com/home, getting page!" fullword ascii
      $s14 = "http://%s.blogspot.com" fullword ascii
      $s15 = "https://login.facebook.com/login.php?m=m&refsrc=m.facebook.com%2F" fullword ascii
      $s16 = "[FACEBOOK] Exiting SPAM - Got redirect to login.php ('Location:' header)" fullword ascii
      $s17 = "https://www.blogger.com/signup.g" fullword ascii
      $s18 = "http://www.blogger.com/html?blogID=%s" fullword ascii
      $s19 = "http://www.blogger.com/home?pli=1" fullword ascii
      $s20 = "http://www.blogger.com/home" fullword ascii
   condition:
      1 of ($x*) or all of them
}


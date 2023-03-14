rule Cutwail_2016 : trojan
{
strings:
    $s1 = "188.64.170.79:443#188.64.170.208:443"

condition:
    $s1
}

rule Cutwail_2016_2 : trojan
{
strings:
    $s1 = "siberia2\\loader"
    $s2 = "svchost.exe"
    $s3 = "SigningHash"
    $s4 = "T1X1"
    $s5 = "ResumeThread"


condition:
    4 of them
}

rule Cutwail_2016_3 : trojan
{
strings:
    $s1 = "svchost.exe"
    $s2 = "%s\\%s.exe"
    $s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
    $s4 = "UndefinedOS"
    $s5 = "http://%s/"


condition:
    4 of them
}
rule Fobber : Stealer
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-05"
        sample = "md5: 9bc5cb7268012c9786e2e107b64a1adb"


    strings:
        $s1 = "GetProcessWindowStation"
        $s2 = "GetTickCount64"
        $s3 = "5(.% 4*-#c7c>?<g3;%;|%!>82<1==?*"
        $s4 = "3;%;|%!>82<1==?*"
    condition:
        3 of them
}

rule Fobber_Packer : Stealer
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-06-23"
        sample = "md5: 9bc5cb7268012c9786e2e107b64a1adb"


    strings:
        $s1 = {2a 08 3d de 00 00 e8 b3 14 00 00 8b a7 fd d7 f1}
        $s2 = {f2 30 79 82 f5 90 c6 01 16 4e 96 7f 09 bc 1d 74}
    condition:
        all of them
}


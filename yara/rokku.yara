rule Rokku : Ransomware
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-08-16"
        description = "Reflective DLL loading. See https://blog.malwarebytes.com/threat-analysis/2016/04/rokku-ransomware/"
        sample = "md5: 97512f4617019c907cd0f88193039e7c"

    strings:
         $s1 = "YOUR FILE HAS BEEN LOCKED"
         $s2 = "AES for Intel AES-NI, CRYPTOGAMS by <appro@openssl.org>"

    condition:
        1 of them
}

rule Shakti1 : Ransomware
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-08-16"
        description = "See https://blog.malwarebytes.com/threat-analysis/2016/08/shakti-trojan-stealing-documents/"
        sample = "md5: b1380af637b4011e674644e0a1a53a64"

    strings:
         $s1 = "SandboxieControlWndClass"
         $s2 = "opera.exe"
         $s3 = "ReflectiveLoader"

    condition:
        all of them
}

rule Shakti2 : Ransomware
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-08-16"
        description = "See https://blog.malwarebytes.com/threat-analysis/2016/08/shakti-trojan-stealing-documents/"
        sample = "md5: b1380af637b4011e674644e0a1a53a64"

    strings:
         $s1 = "PPTX"
         $s2 = "POST"
         $s3 = "-Update"

    condition:
        all of them
}
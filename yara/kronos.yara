rule kronos : banker
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-08-16"
        description = "See https://www.lexsi.com/securityhub/overview-kronos-banking-malware-rootkit/?lang=en"
        sample = "md5: f085395253a40ce8ca077228c2322010"

    strings:
         $s1 = "HTTP"
         $s2 = "POST"
         $s3 = "RtlComputeCrc32"
         $s4 = "chrome.dll"
         $s5 = "ssl3.dll"
         $s6 = "Kronos"

    condition:
        all of them
}

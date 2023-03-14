rule Blackenergy : APT
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-08-16"
        description = "DLL injection. See http://malware-unplugged.blogspot.de/2016/02/blackout-memory-analysis-of-blackenergy.html"
        sample = "md5: 1d6d926f9287b4e4cb5bfc271a164f51"

    strings:
         $s1 = "RSA1"
         $s2 = "RkLoadKernelImage"
         $s3 = "main.dll"
         $s4 = "explorer.exe"
         $s5 = "SrvSendHttpRequest"

    condition:
        4 of them
}
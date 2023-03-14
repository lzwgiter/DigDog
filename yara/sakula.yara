rule Sakula : APT
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-05"
        sample = "md5: 191696982f3f21a6ac31bf3549c94108"

    strings:
        $s1 = "AdobeUpdate.exe"
        $s2 = "BLACKBOX.DLL"
        $s3 = "CLBCatQ.DLL"
        $s4 = "CryptDllDecodeObjectEx"
        $s5 = "WinSta0"

    condition:
        all of them
}


rule Sakula2 : APT
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-06-24"
        sample = "md5: 191696982f3f21a6ac31bf3549c94108"

    strings:
        $s1 = "AdobeUpdate.exe"
        $s2 = "newimage.asp"
        $s3 = "www.savmpet.com"
        $s4 = "SetThreadPriority"
        $s5 = "MicroMedia"

    condition:
        4 of them
}

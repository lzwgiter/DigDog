rule Symmi : Malware
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-01"
        description = "Symmi. See http://www.johannesbader.ch/2015/01/the-dga-of-symmi/"
        version = "2016-01"
        sample = "md5: b1f6be6030bb78087e6d710b2c229b48"

    strings:
        $random1 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; SV1)"
        $random2 = "script"
        $random3 = "FCIFlushCabinet"
        $random4 = "POST"
        $random5 = "If-None-Match: %s"
        $random6 = "Basic"


    condition:
        5 of ($random*)
}


rule Symmi_packer : Malware
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-01"
        description = "Symmi. See http://www.johannesbader.ch/2015/01/the-dga-of-symmi/"
        version = "2016-01"
        sample = "md5: b1f6be6030bb78087e6d710b2c229b48"

    strings:
        $random1 = "IsDebuggerPresent"
        $random2 = "Microsoft Visual C++ Runtime Library"
        $random3 = "PostThreadMessageW"
        $random4 = "GetProcAddress"
        $random5 = "RtlUnwind"
        $random6 = "IsValidCodePage"


    condition:
        5 of ($random*)
}

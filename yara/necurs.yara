rule Necurs : Rootkit
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-05"
        description = "Necurs is a rootkit. See https://blogs.technet.microsoft.com/mmpc/2014/06/09/msrt-june-2014-necurs/"
        sample = "md5: dbd78bf24153cccf4253b1c890f3b476"

    strings:
        $random1 = "findme"
        $random2 = "findme1"
        $random3 = "findme2"
        $random4 = "findme3"
        $random5 = "facebook.com"

    condition:
        4 of ($random*)
}

rule Necurs_Packer : Rootkit
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-06-26"
        description = "Necurs is a rootkit. See https://blogs.technet.microsoft.com/mmpc/2014/06/09/msrt-june-2014-necurs/"
        sample = "md5: dbd78bf24153cccf4253b1c890f3b476"

    strings:
        $code1 = {558BEC81ECD400000053568B7508576A}
        $random2 = "RtlDecompressBuffer"
        $random3 = "RtlCompressBuffer"
        $random4 = "GetProcAddress"
        $random5 = "UnmapViewOfFile"

    condition:
        3 of ($random*) and $code1
}


rule Tuscas : Trojan
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-02"
        description = "Tuscas is a banking Trojan. See http://stopmalvertising.com/malware-reports/analysis-of-tuscas.html"
        version = "2014-08"
        sample = "md5: 77834a1ed2293561be11e4735482263f"

    strings:
        $network1 = "/bing"
        $network1 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)"
        $network1 = "WS2_32.dll"
        $network1 = "WININET.dll"
        $network1 = "Host"
        $network1 = "User-Agent"

        $ins1 = "pushad"
        $ins2 = "cwde"
        $ins3 = "scasb"
        $ins4 = "loopnz"
        $ins5 = "fdivr"

    condition:
        all of ($network*) and all of ($ins*)
}

rule Tuscas_packer : Trojan
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-02"
        description = "Tuscas is a banking Trojan. See http://stopmalvertising.com/malware-reports/analysis-of-tuscas.html"
        version = "2014-08"
        sample = "md5: 77834a1ed2293561be11e4735482263f"

    strings:
        $ins1 = "aPLib v1.01"
        $ins2 = "aplib.dll"
        $ins3 = "_aP_pack"

    condition:
        all of them
}

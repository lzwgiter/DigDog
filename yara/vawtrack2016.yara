rule Vawtrack : Trojan
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-02"
        description = "Vawtrack is a banking Trojan. See http://stopmalvertising.com/malware-reports/analysis-of-vawtrak.html"
        version = "2016-01"
        names = "Vawtrack, Neverquest"
        sample = "md5: 26cecbd85b6c4968952ed366753f085a"

    strings:
        $random1 = "Cookie: disclaimer_accepted=true"
        $random2 = "Cache-Control: max-age=0"
        $random3 = "PID: %u [%0.2u:%0.2u:%0.2u]"
        $random4 = "MiniDumpWriteDump"
        $random5 = "D:(A;OICI;GA;;;WD)"

    condition:
        all of ($random*)
}

rule Vawtrack2 : Trojan
{
    strings:
        $random1 = "F:\\Execute\\Crystal\\transportationa.pdb"
        $random2 = "RSDS"
        $random3 = "developers segmentation RunWorkflow"
        $random4 = "IsDebuggerPresent"
        $random5 = "QueryPerformanceCounter"

    condition:
        4 of ($random*)
}


rule Sality : Malware
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-01"
        description = "Sality is omnipotent..."
        version = "2016-01"
        sample = "md5: 2df5ef505fab24649818f58a5ff21850"

    strings:
        $random1 = "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)"
        $random2 = "monga_bonga"
        $random3 = "[AutoRun]"
        $random4 = "AntiVirusDisableNotify"
        $random5 = "SavRoam"
        $random6 = "C:\\Windows\\system32\\drivers\\mmmmn.sys"


    condition:
        5 of ($random*)
}

rule Sality_packer : Malware
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-01"
        description = "Sality is omnipotent..."
        version = "2016-01"
        sample = "md5: 2df5ef505fab24649818f58a5ff21850"

    strings:
        $random3 = "sobaka1.gif"
        $random4 = "sobakavolos.gif"

    condition:
        all of them
}

rule Matnsu2016 : Dropper
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-01"
        version = "2016-02"
        sample = "d21f6e2fc7bd528240b3f5215d2015a0e290cc0c828487193a1fa2d0a9197ccf"

    strings:
        $domain1 = "ngyjulid.com"
        $domain2 = "gustoslamp.net"
        $domain3 = "layanip.com"
        $domain4 = "fordshunt.com"
        $domain5 = "formepaar.com"

    condition:
        3 of ($domain*)
}

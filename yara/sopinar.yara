rule Sopinar : Dropper
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-01-29"
        description = "Sopinar is a malware droppper. See http://www.virusradar.com/en/Win32_Sopinar.A/description"
        version = "2015-11"
        names = "Sopinar"
        sample = "md5: 6c5845c788b04e47ead71ee4c287d769"

    strings:
        $domain1 = "autionalertybrider.pw"
        $domain2 = "avendatortiespr.pw"

    condition:
        all of ($domain*)
}

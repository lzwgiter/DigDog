rule Rebhip : Stealer
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-05"
        sample = "md5: 4b2e5c2b226f4f4f9482560b085ece69"


    strings:
        $s1 = "Software\\Borland\\Delphi\\Locales"
        $s2 = "GetChromePass"
        $s3 = "\\Internet Explorer\\iexplore.exe"
        $s4 = "objAntiVirus.displayName"

    condition:
        all of them
}

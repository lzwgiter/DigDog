rule SchwarzeSonne : RAT
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-01"
        description = "Sopinar is a RAT. See https://rstforums.com/forum/28058-schwarze-sonne-rat-0-9-a.rst"
        names = "Schwarze Sonne"
        sample = "md5: 4bcf1d340c43b8bb93f3129c3c651ffc"

    strings:
        $delphi1 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $delphi2 = "Software\\Borland\\Locales"
        $delphi3 = "TOwnerDrawState"
        $delphi4 = "TThreadLocalCounter"
        $delphi5 = "TUnitHashArray"
        $delphi6 = "MAINICON"
        $delphi7 = "TKeylogger"

        $rat1 = "\\logs.dat"
        $rat2 = "BIOSVendor"
        $rat3 = "SELECT * FROM logins"
        $rat4 = "Remote computer is crashed..."
        $rat5 = "Remote computer is logoff..."
        $rat6 = "HuntHTTPDownload"
        $rat7 = "uWebcam"

    condition:
        5 of ($delphi*) and 6 of ($rat*)
}

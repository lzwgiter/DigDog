rule Remtasu : RAT
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-01"
        names = "Remtasu"
        sample = "md5: 17b1656f332b6b746fb044d27c8f433d"

    strings:
        $delphi1 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $delphi2 = "TUSBSpreader"
        $delphi3 = "UnitInjectServer"
        $delphi4 = "UnitCryptString"
        $delphi5 = "TUnitInfectUSB"
        $delphi6 = "TServerKeylogger"
        $delphi7 = "YUnitBinder"
        $delphi8 = "OThreadUnit"
        $delphi9 = "dstub"
        $delphi10 = "TGetPlugin"

    condition:
        8 of ($delphi*)
}

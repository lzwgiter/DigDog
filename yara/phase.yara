rule Phase : Stealer
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-01-29"
        description = "Fork of Napolar. See http://www.xylibox.com/2015/01/phase-win32phasebot-a.html"
        version = "2014-12"
        names = "PhaseBot"
        sample = "md5: d1446326bf1c69ea9df6e65bd472f358"

    strings:
        $random1 = "CHROME.DLL"
        $random2 = "rundll32.exe javascript:"
        $random3 = "%d.%d.%d.%d"
        $random4 = "PowerShell"
        $random5 = "Phase"
        $random6 = ".ps1"
        $network1 = "g=%s&i=%d.%d.%d.%d&u=%s&p=%s"
        $network2 = "g=%s&u=%d&s=%d&p=%d"
        $network3 = "b=%d&d=%s&u=%s"
        $network4 = "Communicate"
        $network5 = "g=%s&w=%d.%d.%d&b=%d&d=%d&p=%d&m=%d"
        $network6 = "Content-Type: application/x-www-form-urlencoded"

    condition:
        3 of ($random*) and 4 of ($network*)
}


rule Phase_powershell : Stealer
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-01-29"
        description = "Fork of Napolar. See http://www.xylibox.com/2015/01/phase-win32phasebot-a.html"
        version = "2014-12"
        names = "PhaseBot"
        sample = "md5: d1446326bf1c69ea9df6e65bd472f358"

    strings:
        $random1 = "IyBSZWFkIEFuZCBFeGVjdXRlIFJjNCBFbmNyeXB0ZWQgU2hlbGxDb2RlIEZyb20gVGhlIFJlZ2lzdHJ5IA0KDQojIFNldCBSZWdpc3RyeSBLZXkNCiRzUmVnaXN0"

    condition:
        all of them
}


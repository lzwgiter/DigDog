rule Teerac : ransomware
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-05"
        description = "Teerac is another ransomware. See https://blogs.technet.microsoft.com/mmpc/2015/11/09/msrt-november-2015-detection-updates/"
        version = "2016-01"
        sample = "md5: cebc3e8dfdcd25ccda7e5a60cdefc601"

    strings:
        $random1 = "</assembly>PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD"
        $random2 = "rack-core.bin"

    condition:
        all of them
}

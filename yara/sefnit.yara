rule Sefnit : clickfraud
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-04"
        description = "Sefnit is used for click fraud. See https://blogs.technet.microsoft.com/mmpc/2013/09/25/mevade-and-sefnit-stealthy-click-fraud/"
        version = "2016-01"
        sample = "md5: 1809960249a77fffa389b8d1710be33b"

    strings:
        $hex_string = { 21 45 f4 5b 8b ca 5b 2b d9 01 4d d8 51 23 45 ec }


    condition:
        $hex_string
}

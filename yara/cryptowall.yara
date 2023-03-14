rule Cryptowall : Ransom
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-02"
        description = "Cryptowall is ransomware. See http://stopmalvertising.com/malware-reports/cryptowall-behind-the-scenes.html"
        version = "2016-01"
        sample = "md5: 77834a1ed2293561be11e4735482263f"

    strings:
        $random1 = "_Y0zi"
        $random2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $random7 = "crypt3007"

    condition:
        2 of ($random*)
}

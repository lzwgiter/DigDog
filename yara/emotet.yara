rule Emotet : Banker
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-06-24"
        sample = "md5: e78a7f73a77a79f8e18dc1c5807013c6"

    strings:
        $domain1 = "http://158.255.238.209:8080"
        $domain2 = "http://200.159.128.132:8080/1640f6aa/-1524294671.php"
        $domain3 = "http://103.245.153.70:8080/338d301f/-2132222652.php"
        $user = "USERX914ECCEB0E_DE_7eeab5d75b470636"


    condition:
        1 of them
}

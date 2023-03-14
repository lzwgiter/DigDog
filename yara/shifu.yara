rule Shifu : banker
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-08-16"
        description = "DLL injection. See https://www.virusbulletin.com/virusbulletin/2015/11/shifu-rise-self-destructive-banking-trojan"
        sample = "md5: e60f72ffa76386079f2645be2ed84e53"

    strings:
         $s1 = "Z:\\coding\\project\\main\\payload\\payload.x86.pdb"

    condition:
        $s1
}
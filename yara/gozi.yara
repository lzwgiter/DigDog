rule gozi_avalanche : trojan
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2015-09-15"
        updated = "-"
        version = "1"
        description = "Gozi/Ursnif version used in the Avalanche infrastructure"
        sample = "213262f992fbfb2fd1e189a3d9f0a14b"
    /* updates:
           2015-09-15: initial signature
    */

    strings:
        /*
        contains usable unencrypted strings in .bss section
        http://blog.notesonmalware.se/post/2014/10/09/Ursnif-still-in-active-development
        */

        //
        $cnc_field_0 = "version=%u&soft=1&user=%s&server=%u&id=%u&crc=%x" ascii wide
        $cnc_field_1 = "soft=1&version=%u&user=%s&server=%u&id=%u&type=%u&name=%s" ascii wide
        $cnc_field_2 = "/data.php?version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s" ascii wide
        $cnc_field_3 = "http://constitution.org/usdeclar.txt" ascii wide
        $cnc_field_4 = "grabs=" ascii wide
        $cnc_field_5 = "Content-Disposition: form-data; name=\"upload_file\"; filename=\"%s\"" ascii wide

        // banking
        $banking_0 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT %u.%u%s)" ascii wide
        $banking_1 = "PR_Write" ascii wide
        $banking_2 = "NSPR4.DLL" ascii wide

        // other strings
        $other_0 = "reg.exe query" ascii wide
        $other_1 = "Salt" ascii wide
        $other_2 = "network.http.spdy.enabled" ascii wide
        $other_3 = "DLL load status: %u" ascii wide
        $other_4 = "PluginRegisterCallbacks" ascii wide
        $other_5 = "%02u-%02u-%02u %02u:%02u:%02u" ascii wide


    condition:
       ((3 of ($cnc_field_*)) and (2 of ($banking_*)) and (3 of ($other_*)))
}

rule gozi_packer : trojan {

    strings:
        $s1 = "FIBRE"
        $s2 = "NtQuerySystemInformation"
        $s3 = "NtCreateSection"
        $s4 = "ASCIT8"
        $s5 = "VirtualProtectEx"

    condition:
        4 of them
}
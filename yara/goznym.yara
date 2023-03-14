rule GozNym : Banking
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-05-17"
        description = "GozNym is a merger of Nymaim and Gozi. See https://securityintelligence.com/meet-goznym-the-banking-malware-offspring-of-gozi-isfb-and-nymaim/"

    strings:
        $entry_point = {31 C0 40 90 C3} // see http://joe4security.blogspot.de/2016/04/nymaim-evading-sandboxes-with-api.html

        // borrowed from older rule by Daniel Plohmann
        // reading and writing the return address is suspicious
        /*
          push ebp
          mov ebp, esp
          push eax
          mov eax, [ebp+4]
        */
        $return_addr_modification_0 = {55 89 E5 50 8B 45 04}
        /*
          add [ebp+4], eax
          pop eax
          leave
          retn 8
        */
        $return_addr_modification_1 = {01 45 04 58 C9 C2 08 00}

    condition:
        $entry_point and (all of ($return_addr_modification_*))
}
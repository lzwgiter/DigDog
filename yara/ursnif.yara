rule Ursnif : ransomware
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-04"
        description = "Fork of Rovnix. See http://blog.trendmicro.com/trendlabs-security-intelligence/ursnif-the-multifaceted-malware/"
        version = "2016-01"
        sample = "md5: c534c82eca5ea59e164effde8c0fa4f6"

    strings:
        $internal1 = "ISFB_%04x: ISFB client DLL version %u.%u, build %u, group %u"
        $internal2 = "ISFB_%04x: Attached to 32-bit process by thread 0x%04x at 0x%p"
        $internal3 = "CRYPTO: Encrypting string %s"
        $internal4 = "ISFB_%04x: DS verification succesed."
        $internal5 = "ISFB_%04x: DS verification failed."
        $internal6 = "ISFB_%04x: SSL method table not found. Unsupported CHROME/OPERA version."
        $internal7 = "[NWindowStart] failed to start thread, err = %lu"
        $internal8 = "ACTIVDLL_%04x: No module found for the target process (%u) architecture"
        $internal9 = "KEYLOG: Adding key to a buffer: 0x%x, %C"

    condition:
        7 of ($internal*)
}

rule pandabanker : banking_trojan
{
  meta:
    author = "thomas.barabosch@fkie.fraunhofer.de"
    description = "Banking trojan based on Zbot (see https://www.proofpoint.com/us/threat-insight/post/panda-banker-new-banking-trojan-hits-the-market)"

  strings:
    $s1 = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890"
    $s2 = "%s://%s"
    $s3 = "HTTP/1"
    $s4 = "If-Modified-Since"
    $s5 = "%u.%u"
    $s6 = "GetModuleHandleAFlushInstruction"

  condition:
    4 of them
}

rule pandabanker_shellcode : banking_trojan
{
  meta:
    author = "thomas.barabosch@fkie.fraunhofer.de"
    description = "Banking trojan based on Zbot (see https://www.proofpoint.com/us/threat-insight/post/panda-banker-new-banking-trojan-hits-the-market)"

  strings:
    $s1 = "8KJw"
    $s2 = "A7w"
    $s3 = "鉐8w"

  condition:
    all of them
}

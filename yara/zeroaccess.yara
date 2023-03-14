rule zeroaccess : injector
{
	strings:
		$string1 = "VC20XC00U"
		$string2 = "RSA1"
		$string3 = "=cnctt^=recvt"
	condition:
		all of them
}

rule zeroaccess_driver : injector
{
	strings:
		$string1 = "!This program cannot be run in DOS mode."
		$string2 = "acmDriverAddA"
		$string3 = "NtFs"
	condition:
		all of them
}



rule feodo : injector
{
	strings:
		$string1 = "__VIEWSTATEENCRYPTED"
		$string2 = "shell\\Autoplay\\command=%S"
		$string3 = "[autorun]"
	condition:
		all of them
}

rule feodo_packer : injector
{
	strings:
		$string1 = "Host: hmvmgywkvayilcwh.ru:8080"
		$string2 = "User-Agent: Mozilla/5.0"
		$string3 = "GetSignedDataMsg"
	condition:
		all of them
}

rule napolar : injector
{
	strings:
		$string1 = "\\\\.\\pipe\\napSolar"
		$string2 = "\\tor.bin"
	condition:
		all of them
}


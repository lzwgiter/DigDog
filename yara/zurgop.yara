rule zurgop : injector
{
	strings:
		$string1 = "AutoItv3CCleanerWIC"
		$string2 = "Mozilla/4.0"
		$string3 = "cmd=getload&login="
	condition:
		all of them
}


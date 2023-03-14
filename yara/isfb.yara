rule isfb : injector
{
	strings:
		$string1 = "MakeScreen"
		$string2 = ".set CabinetName1=\"%s\""
		$string3 = "failed start tasklist - %u"
	condition:
		all of them
}






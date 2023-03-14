rule lamechi : injector
{
	strings:
		$code1 = { C8 00 00 00 E8 04 00 00 00 D1 09 83 7C } 
		$string1 = "C:\\WINDOWS\\system32\\runouce.exe"	
	condition:
		all of them
}

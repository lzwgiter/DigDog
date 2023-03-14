rule urausy : injector
{
	strings:	
		$code1 = {8d 49 f8 79 09 33 c0 03 41 40 75 09 eb 0b}
	condition:
		all of them
}

rule urausy2 : injector
{
	strings:
		$s1  = "The original hash -- phase 2."
		$s2  = "GetCurrentProcess"
		$s3  = "FindWindowW"
		$s4  = "IsDebuggerPresent"
	condition:
		all of them
}

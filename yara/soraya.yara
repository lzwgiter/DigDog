rule soraya : injector
{
	strings:	
		$string1 = "SorayaV1.1"
		$string2 = "POSMainMutex"
	condition:
		all of them
}

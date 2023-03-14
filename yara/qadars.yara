rule qadars : injector
{
	strings:
		$bytes = { 55 8b ec 81 ec c8 04 00 00 c6 85 e4 fe ff ff 20 }

	condition:
		all of them
}

rule qadarspacker : injector
{
	strings:
		$s1 = "SVWP"
		$s2 = "SVW3"
		$s3 = "OutputDebugStringA"
		$s4 = "LoadLibraryA"
		$s5 = "GetModuleHandleA"

	condition:
		all of them
}

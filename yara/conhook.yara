rule conhook : injector
{
	strings:
		$code = {b1 03 e8 72 00 00 00 73 f6 3b fb}
	condition:
		all of them
}


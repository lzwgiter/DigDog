rule gamker : injector
{
	strings:
		$string1 = "Omikron\\MCSign"
		$string2 = "ELBA5\\ELBA_data"
		$string3 = "payment_processor"
	condition:
		2 of them
}


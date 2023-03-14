rule Cryptolocker : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-28"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Cryptolocker"
		sample = "md5: bc11c93f1b6dc74bf4804a35b34d9267"

	strings:
		$string_2 = "%BITCOIN_ADDRESS%"
		$string_3 = "%AMOUNT_EUR%"
		$text_1 = "To decrypt files you need to obtain the \\b private key.\\par"
		$text_2 = "Any attempt to remove or damage this software will lead to the immediate destruction of the private key by server."
		$test_3 = "the private key for this computer, which will automatically decrypt files, you need to pay"

	condition:
		any of them
}

rule Cryptolocker_packer : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-28"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Cryptolocker"
		sample = "md5: bc11c93f1b6dc74bf4804a35b34d9267"

	strings:
		$string_2 = {55 89 E5 53 57 56 8B 75 10 2B 75 14}
		$string_3 = {55 89 E5 53 57 56 8B 55 08 85 D2 74 5A 03 55 0C}


	condition:
		any of them
}



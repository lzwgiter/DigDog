rule Atrax : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-28"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Atrax"
		sample = "md5: 96fecadd17682ce64e68887f018e12e3"

	strings:
		$software_1 = "Proxy CONNECT followed by %zd bytes of opaque data. Data ignored (known bug #39)"
		$software_2 = "%sAuthorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", cnonce=\"%s\", nc=%08x, qop=%s, response=\"%s\""
		$software_3 = "Visual C++ CRT: Not enough memory to complete call to strerror."

		$string_1 = "BotDll.dll"
		$url = "iloii7dnyotii3gr.onion"

		// checks for virtualizaition
		$virt_1 = "VMware"
		$virt_2 = "VBOX"
		$virt_3 = "DiskVirtual_HD"


	condition:
		all of them
}

rule Atrax_packer: injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-28"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Atrax"
		sample = "md5: 96fecadd17682ce64e68887f018e12e3"

	strings:
		$s1 = "TcaEjiucMc"
        $s2 = "AcrVtieGbbtcuu"
        $s3 = "ExitProcess"
        $s4 = "!This program cannot be run in DOS mode."



	condition:
		all of them
}
rule Urlzone : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Urlzone / Bebloh"
		sample = "md5: 79ba32519af63486facaa262d88ee4ea"

	strings:
		$infalte = "inflate 1.2.4 Copyright 1995-2010 Mark Adler"
		$urlpart = "/p8/amid.php"
		$software = "FTPVoyager.exe"

	condition:
		all of them
}

rule Urlzone_shellcode : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Urlzone / Bebloh"
		sample = "md5: 79ba32519af63486facaa262d88ee4ea"

	strings:
		$infalte = "www.google.com"
		$urlpart = "MEOW"
		$software = "defua.exe"

	condition:
		all of them
}

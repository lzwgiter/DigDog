rule Parite : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Parite"
		sample = "md5: 475d456fa0062bb5323f1f002ac143da"

	strings:
		$shellcode = {00 00 00 00 59 e9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 00
									00 00 00 00 00 00 00 e8 ?? ?? ?? ?? 0a 00}

	condition:
		all of them
}

rule Parite2 : injector
{

	strings:
		$s1 = "TParasite"
		$s2 = "TApiTable"
		$s3 = "vcltest3.dll"
		$s4 = "_RWSTDMutex"
		$s5 = "streams.c"

	condition:
		4 of them
}

rule Parite_heap : injector
{

	strings:
		$s1 = "@$xp$12Nmudp@TNMUDP"
		$s2 = "AttachHook"
		$s3 = "Debug"
		$s4 = "___CPPdebugHook"

	condition:
		all of them
}



rule Betabot : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-28"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Betabot"
		sample = "md5: 2976af9b6550823b7786c2f66514902d"

	strings:
		$string_1 = "ProcCallEngine"
		$string_2 = "MethCallEngine"
		$string_3 = "Project1" // winning
		$vb_aes = "bytPassword"
		$method_1 = "NtWriteVirtualMemory"
		$method_2 = "SetThreadContext"

	condition:
		all of them
}

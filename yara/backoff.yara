rule Backoff : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-28"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Backoff"
		sample = "md5: d0c74483f20c608a0a89c5ba05c2197f"

	strings:
		$string_1 = "PasswordUndsa8301nskal"
		$string_2 = "uyhnJmkuTgD"
		$string_3 = "SHGetSpecialFolderPathA"
		$string_4 = "\\winserv.exe"

	condition:
		all of them
}

rule Backoff_packer : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-28"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Backoff"
		sample = "md5: d0c74483f20c608a0a89c5ba05c2197f"

	strings:
		$string_1 = "SECURITY_DESCRIPTOR"
		$string_2 = "!This program cannot be run in DOS mode"
		$string_3 = "[Autorun]"
		$string_4 = "Open=backoff"

	condition:
		all of them
}
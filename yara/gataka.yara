rule Gataka : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Gataka"
		sample = "md5: 5d79424b68f51c794927b2b10f12f0f5"

	strings:
		$bzip2 = "combined CRCs: stored = 0x%08x, computed = 0x%08x"
		$abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		$specials = "!\"#$%&'()*+,-./0123"
		$string = "CMainMan"

	condition:
		all of them
}

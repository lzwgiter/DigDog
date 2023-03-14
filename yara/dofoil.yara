rule Dofoil : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-28"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Dofoil"
		sample = "md5: e51298ee0ded1c38bcc2f5590ff739f9"

	strings:
		$string_1 = "cmd=getload&login="
		$string_2 = ":Zone.Identifier"
		$string_3 = "&personal=ok"
		$string_4 = "cmd=getplugins"
		$string_5 = "Accept-Language: en-gb;q=0.8,en;q=0.7"

	condition:
		all of them
}

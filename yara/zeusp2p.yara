rule Zeus_p2p : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Zeus (p2p)"
		sample = "md5: 203f031a7d41fb247d0bd55bb8b1f382"

	strings:
		$string_1 = "##$%&'())))))**+,-./JJJJJJJJ00J1234555676789:;<:;<JJJJJ=>?@ABCDEFG"
		$string_2 = "MKACTIVITY"

		$string_3 = "Invalid parameter passed to C runtime function."
		$string_4 = "userenv.dll"


	condition:
		all of them
}

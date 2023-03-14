rule Dorkbot : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-28"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Dorkbot"
		sample = "md5: 393b4c117e15fbcfe56f560a8e6a3f0c"

	strings:
		$string_1 = "%s.Blocked \"%s\" from removing our bot file!" // :(
		$string_2 = "%s.p10-> Message to %s hijacked!"
		$string_3 = "%s.Blocked \"%S\" from creating \"%S\" - \"%s\" will be removed at reboot!"
		$string_4 = "*paypal.*/webscr?cmd=_login-submit*"
		$method = "WriteProcessMemory"

	condition:
		all of them
}

rule Gamker : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-21"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Gamker"
		sample = "md5: 02106fd5b702db4665889e51d6f52643, c9197f34d616b46074509b4827c85675"

	strings:
		// knows some good games ;)
		$game_1 = "\\DragonAge2.exe"
		$game_2 = "\\mafia2.exe"
		$bot = "botid=%s&ver=5.3.12&up=%u&os=%03u&ltime=%s%d&token=%d&cn=testx&av=%s"
		// looking for avs
		$av_1 = "Software\\KasperskyLab\\protected"
		$av_1 = "Microsoft\\Microsoft Antimalware"
		$av_1 = "Software\\KasperskyLab\\protected"
		$string_1 = "iexplore.exe|opera.exe|firefox.exe|chrome.exe|maxthon.exe|java.exe|javaw.exe|plugin-container.exe|acrobat.exe|acrod32.exe"
		$string_2 = "BUH|BANK|ACCOUNT|CASH|KASSA|DIREK|FINAN|OPER|FINOTDEL|DIRECT|ROSPIL"

	condition:
		4 of them
}

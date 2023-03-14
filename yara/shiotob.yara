rule shiotob : injector
{
	strings:	
		$string1 = "ITBEGINBLOCKHOOK"
		$string2 = "truesteak.net/fen/ret.php"
		$string3 = "chrome.exe"
	condition:
		all of them
}

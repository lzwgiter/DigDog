rule vundo : injector
{
	// Vundo seems to inject via DLL injection
	// Undetected by volatility malfind
	strings:
		$string_1 = "Mozilla/4.0 (compatible; MSIE 6.0) WinNT 5.1"
		$string_2 = "http://82.98.235.208/form/index.html"
		$string_3 = "85.12.43.102"

	condition:
		all of them
}

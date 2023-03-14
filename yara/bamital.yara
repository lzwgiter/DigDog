rule Bamital : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-28"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Bamital"
		sample = "md5: 7f2c85055f1952395450d963208c7bf7"

	strings:
		$string_1 = "Gentee installer"
		$string_2 = "LOAD: GETMODULEFILENAME failed PID=%ld | stringID=%ld | str=%S | flags=%d | hr = %X"
		$string_3 = "HEROSOFTSOUTHERN"
		$string_4 = "LOAD: INIT failed PID=%ld | stringID=%ld | str=%S | flags=%d | hr = %X"
		$string_5 = "ThraexSoftware.AstrumInstallWizard"
		$string_6 = "ReadProcessMemory failed while trying to read PebBaseAddress"
		$string_7 = "Failed to read the peb from the process"

		$method_1 = "SXS: %s() NtCreateSection() failed. Status = 0x%x."
		$method_2 = "SXS: %s() NtMapViewOfSection failed"

	condition:
		6 of them
}

rule bamital_2 : trojan
{
strings:
    $s1 = "explorer.exe"
    $s2 = "&version="
    $s3 = "SCSIDISK"
    $s4 = "www.altavista.com"
    $s5 = "Podmena"


condition:
    4 of them
}


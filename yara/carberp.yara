rule Carberp : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-28"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Carberp"
		sample = "md5: 02e693a4a66c104541dec55f417d29b9"

	strings:
		$string_1 = "GET /stat?uptime=%d&downlink=%d&uplink=%d&id=%s&statpass=%s&comment=%s HTTP/1.0"
		$string_2 = "update PAYDOCRU set DOCUMENTDATE=?, STATUS=30001 where PAYERACCOUNT=? and DOCUMENTDATE=? and DOCUMENTNUMBER like '%%%s%%'"
		$string_3 = "update ACCOUNT set REST=%s where ACCOUNT=?"
		$string_4 = "cbank_copy.txt" // winning
		$string_5 = "---> <TextLog%d> [%s]"
		$string_6 = "DLL -> Login: '%s', Password system: '%s', Password keys: '%s', Path keys: %s, Client folder: %s"
		$string_7 = "select Param from Config where Code='MyBankId'"

	condition:
		any of them
}

rule Carberp2 : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-28"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Carberp"
		sample = "md5: 02e693a4a66c104541dec55f417d29b9"

	strings:
		$string_1 = "DeleteFileA"
		$string_2 = "GetWindowThreadProcessId"
		$string_3 = "OutOfHibernation"
		$string_4 = "WS2_32.dll"
		$string_5 = "AgentPassive.log"
		$string_6 = "Amount"
		$string_7 = "Account2"

	condition:
		5 of them
}

rule Carberp3 : injector
{
	meta:
		author = "Niklas Bergmann <niklas.bergmann<at>fkie.fraunhofer.de>"
		date = "2016-01-28"
		description = "Rules generated for featurememdumpdetection"
		version = "1.0"
		names = "Carberp"
		sample = "md5: 02e693a4a66c104541dec55f417d29b9"

	strings:
		$string_1 = "svchost.exe"
		$string_2 = "rkVi1ECizVg.dat"
		$string_3 = "mswsock.dll"
		$string_4 = "NtQueryInformationFile"

	condition:
		all of them
}
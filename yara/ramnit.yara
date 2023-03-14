rule ramnit : injector
{
	strings:
		$string_1 = "USERPASSCWD CDUPQUITPORTPASVTYPEMODERETRSTORAPPERESTRNFRRNTOABORDELERMD"

	condition:
		all of them
}


rule ramnit2 : injector
{
	strings:
		$string_1 = "ModuleCode"
		$string_2 = "StartRoutine"
		$string_3 = "cookies.txt"

	condition:
		all of them
}

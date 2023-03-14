rule Spyeye2 : injector
{
	meta:
		author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
		date = "2016-06-23"
		version = "1.0"
		names = "Spyeye"
		sample = "md5: 34bd32ff879c86b48e8eaf4d0cfebc8c"

	strings:
		$string_1 = "globplugins"
		$string_2 = "GRABBED"
		$string_3 = "xCryptEncrypt"
		$string_4 = "data_inject"
		$string_5 = "%BOTNAME%"
		$string_6 = "msnmsgr.exe"
		$string_7 = "SpyEye_Init"
		$string_8 = "GetPluginId"

	condition:
		4 of them
}

rule Spyeye3 : injector
{
	meta:
		author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
		date = "2016-06-24"
		version = "1.0"
		names = "Spyeye"
		sample = "md5: 34bd32ff879c86b48e8eaf4d0cfebc8c"

	strings:
		$string_1 = "algonic.exe"
		$string_2 = "config.bin"
		$string_3 = "!EYE"

	condition:
		all of them
}

rule Spyeye4 : injector
{
	meta:
		author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
		date = "2016-06-24"
		version = "1.0"
		names = "Spyeye"
		sample = "md5: 34bd32ff879c86b48e8eaf4d0cfebc8c"

	strings:
		$string_1 = "TakeBotExeMd5Callback"
		$string_2 = "TakeConfigCrc32Callback"
		$string_3 = "guid=%s&ver=%u&ie=%s&os=%u.%u.%u&ut=%s&ccrc=%08X&md5=%s&plg=%s"

	condition:
		all of them
}
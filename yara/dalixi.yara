rule dalixi : injector
{
	strings:
        $string1 = "unionid=%s&mac=%s&iever=1&alexa=0&systemver=2&antisoftware=0&pluginver=%s"
        $string2 = "http://meifawu.com"
        $string3 = "2010042801"
      
	condition:
		all of them
}


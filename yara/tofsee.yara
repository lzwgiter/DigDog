rule Tofsee : Spammer
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-05"
        description = "Tofsee is a spammer. See https://blogs.technet.microsoft.com/mmpc/2014/11/10/msrt-november-2014-tofsee/"
        sample = "md5: b9f908ee4b341b965902d8706fca8398"

    strings:
        $spam1 = "%OUTLOOK_BND_"
        $spam2 = "%TO_USER"
        $spam3 = "%TO_EMAIL"
        $spam4 = "no locks and using MX is disabled"
        $spam5 = "ver_drv_upd"
        $spam6 = "%OUTLOOK_HST"
        $spam7 = "%OUTLOOK_MID"
        $spam8 = "ESMTP"
        $spam9 = "mail from:<%s>"
        $spam10 = "Incorrect respons"

    condition:
        7 of ($spam*)
}

rule Tofsee_templates : Spammer
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-05"
        description = "Tofsee is a spammer. See https://blogs.technet.microsoft.com/mmpc/2014/11/10/msrt-november-2014-tofsee/"
        sample = "md5: b9f908ee4b341b965902d8706fca8398"

    strings:
        $spam1 = "Gasback"
        $spam2 = "Bewusstseinstheologie"
        $spam3 = "Besatzungsstatus"

    condition:
        all of them
}

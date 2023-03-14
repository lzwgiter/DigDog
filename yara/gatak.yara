rule Gatak : Stealer
{
    meta:
        author = "Thomas Barabosch <thomas.barabosch<at>fkie.fraunhofer.de>"
        date = "2016-02-05"
        description = "Gatak is a stealer. See https://blogs.technet.microsoft.com/mmpc/2015/06/09/msrt-june-2015-brobandel/"
        sample = "md5: 4213ab25e8e49a9ea6e671861be4e741"

    strings:
        $cmd1 = "payload_executed"
        $cmd2 = "payload_mem_ok"
        $cmd3 = "payload_type_shell"
        $cmd4 = "payload_type_exe"
        $cmd5 = "payload_file_run_ok"
        $cmd6 = "payload_file_name_ok"
        $cmd7 = "payload_ok"
        $cmd8 = "page_ok"
        $cmd9 = "executed_ok"
        $cmd10 = "XXX_"

    condition:
        7 of ($cmd*)
}

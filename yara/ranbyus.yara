rule ranbyus : banking_trojan
{
  meta:
    author = "Niklas.Bergmann@fkie.fraunhofer.de"
    description = "Banking trojan based on Zbot"

  strings:
    $string_feedback_1 = "Can't inject code to process"
    $string_feedback_2 = "Can't find process with pid:"
    $string_feedback_3 = "Can't read memory of process"

    $string_status_1 = "isBlockedBank"
    $string_status_2 = "isBlockedApp"
    $string_status_3 = "modulesAmount"

    $string_time_boundry = "%02X%02X%02X%02X%02X%04"
    $string_tor_address = ".onion"
    $string_pipe = "\\\\.\\pipe\\testpipe"

  condition:
    4 of them
}

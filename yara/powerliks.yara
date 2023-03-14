rule powerliks : clickfraud
{
  meta:
    author = "thomas.barabosch@fkie.fraunhofer.de"
    description = "Clickfraud (see https://www.uperesia.com/a-closer-look-to-fileless-click-fraud-malware-poweliks)."

  strings:
    $s1 = "type=%s&version=1.0&aid=%s&builddate=%s&id=%s&os=%s_%s"
    $s2 = "powershell.exe"
    $s3 = "error_%u_%x_%x"
    $s4 = "$Parameters,[Parameter(Position=1)]"
    $s5 = "%1d.%1d.%04d_%1d.%1d"

  condition:
    4 of them
}
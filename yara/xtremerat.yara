rule xtremerat : rat
{
  meta:
    author = "thomas.barabosch@fkie.fraunhofer.de"
    description = "RAT (see https://www.fireeye.com/blog/threat-research/2014/02/xtremerat-nuisance-or-threat.html). Also known as cybergate."

  strings:
    $s1 = "SOFTWARE\\Borland\\Delphi\\RTL"
    $s2 = "CyberGate"
    $s3 = "Indy10"
    $s4 = "ChainedProxySV"
    $s5 = "updateUIMd5Hash"
    $s6 = "URLDownloadToFileW"

  condition:
    5 of them
}
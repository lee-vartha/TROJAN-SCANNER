rule Trojan_Backdoor
{
    meta:
        description = "Detects a generic backdoor trojan"
        author = "Lee"
        date = "2025-08-06"
    
    strings:
        $func1 = "CreateRemoteThread" ascii
        $func2 = "VirtualAllocEx" ascii
        $url1 = "This program cannot run in DOS mode" ascii
        $hex1 = { 4D 5A 90 00 }

    condition:
        filesize < 1MB and
        (
            ($func1 and $func2) or
            ($url1 and $hex1) or
            all of them
        )
}
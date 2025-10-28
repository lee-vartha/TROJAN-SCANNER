import "pe"
rule putty_trojan {
    meta: 
        description = "Demo concept to detect example trojan behaviour"
        author = "Lee"
    
    strings:
        $hex1 = { 3d 22 68 74 74 70 3a 2f 2f 73 63 68 65 6d 61 73 }    // "http://schemas"
        $hex2 = {43 72 79 70 74 6f 43 61 72 64 20 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e } // cryptoCard authentication (suspicious)
        $hex3 = {52 65 63 65 69 76 65 64 20 43 72 79 70 74 6f 43 61 72 64} // received cryptocard
        $hex4 = { 62 6c 6f 77 66 69 73 68 } // blowfish = encryption
        $website1 = { 68 6d 61 63 2d 73 68 61 31 2d 39 36 2d 65 74 6d 40 6f 70 65 6e 73 73 68 2e 63 6f 6d   } // hmac-sha1-96-etm@openssh.com
        $website2 = { 77 77 77 2e 63 68 69 61 72 6b 2e 67 72 65 65 6e 65 6e 64 2e 6f 72 67 2e 75 6b  } // www.chiark.greenend.org.nz
        $upx_sig = { 55 8B EC 51 } // UPX

    condition:
    uint16(0) == 0x5A4D and // confirms status of PE

    (
        1 of ($hex*) and
        (
            1 of ($website*) or $upx_sig
        )
    )
}

rule emotet {
    meta:
        description = "detects emotet dropper"
        author = "Lee"
        date = "23/09/2025"

    strings:
    $s1 = "Emotet" ascii wide
    $s2 = "Global\\EmotetMutex" ascii  // mutex for persistance
    $h1 = { 6D 5A 90 00 03 00 00 00 04 00 00 00 00 00 00 00 }

    condition:
    uint16(0) == 0x5A4D and
    pe.number_of_sections > 5 and
    pe.imports("advapi32.dll", "CreateMutexA") and // anti-analysis
    any of ($s*) and
    any of ($h*)
}

// `

rule emotets {
    meta:
        description = "Detects an emotet dropper"
        author = "Lee"
        date = "14/10/2025"

    strings:
        // text strings which match windows API ccalls thats used for reconnaissance and persistence
        // ascii-modifier strings to detect manipulation  
        $s1 = "GetForegroundWindow" ascii // used to interact with active windows
        $s2 = "EnumDisplayMonitors" ascii // sign of reconnaissance as it enumerates monitors
        $s3 = "RegSetValueEx" ascii // sets registry values for persistence or system modification
        $s4 = "RegCreateKeyEx" ascii // creates or opens registry keys

        // text pattersn for C2 servers which is common in emotets network communication
        $netIp1 = "20.190.163.21:443" // IP for C2 malicious server communication
        $netIp2 = "52.148.82.138:443" // IP for C2 malicious server communication
        $netIp3 = "114.114.114.114:53" // suspicious DNS server often used in malware
        $netIp4 = "218.85.157.99:53" // another suspicious DNS server often used in malware
        $netIp5 = "179.5.118.12:80" // http communication IP address
        $netIp6 = "46.22.116.163:7080" // IP for custom port communication

        // text strings for malicious domains and patterns in memory - some mimic actual domains and some represent
        // obfuscated URL via custom encoding for evasion
        $domain1 = "login.live.com" ascii // usually a legimate domain but spoofed - DNS used for communication
        $domain2 = "HTtLHtBHt8Ht.Ht" // obfuscated domain done by emotet
        $domain3 = "7IvD.Lv" // obfuscated/encoded domain 

    condition:
        uint16(0) == 0x5A4D and // PE file check 
        filesize > (100 * 1024) and filesize < (500 * 1024) and // filtering emotet file sizes to reduce false positives
        any of ($s*) and //if any API functions are found, which indicate typical trojan behaviour
        any of ($netIp*) and // if any C2 IP/port is found, flagging network activity
        any of ($domain*) // matches memory patterns (runtime obfuscation)

}

rule exploit_dropper {
    meta:
        description = "Detects exploit dropper behaviour by its unique complier path"
        family = "CustomDroppers"
        author = "Lee"

    strings:
        $s1 = "C:\\Users\\user\\AppData\\Local\\Temp\\cc" ascii nocase
        $s2 = "C:\\Users\\user\\AppData\\Local\\Temp\\cc" wide nocase
        $s3 = "This program cannot be run in DOS mode" ascii
        $h1 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 00 00 00 00 } // PE header

    condition:
        uint16(0) == 0x5A4D and // PE file check
        filesize < 1MB and
        2 of ($s*) and
        $h1
}

rule zeus {
    meta:
        description = "detecting zeuz banking trojan based on config strings and API calls0"
        author = "Lee"
        date = "23/09/25"
        threat = "banking"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zeus"

    strings:
    $s1 = "ZeuS" ascii wide
    $s2 = "FormBook" ascii wide // Variant indicator
    $s3 = "%s\\%s\\%08X.dat" ascii // config file path pattern
    $h1 = { 55 8B EC 83 E4 F8 83 EC 68 56 8B 35 ?? ?? ?? ?? 8B 1D } // API RESOLUTION
    $h2 = { 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 05 E8 ?? ?? ?? ?? } // dynamic API call

    condition:
        uint16(0) == 0x5A4D and // PE file check
        (filesize < 2MB) and
        3 of ($s*) and
        1 of ($h*) 
        // pe.imports("ws2_32.dll", "WSASocketA") // network imports for C2
}


rule demo_trojan {
    meta: 
        description = "Demo concept to detect example trojan behaviour"
        author = "Lee"
    
    strings:
        $s1 = "ThisProgramIsMalicious" ascii nocase
        $s2 = "Trojan" ascii nocase

    condition:
    $s1 or $s2
}

rule vmdetect {
    meta: 
        description = "Detects virtual machine activity"
        author = "Lee"
        date = "18-08-2025"
        version = "1.0"

    strings:
        $vm_tool1 = "VMware" nocase
        $vm_tool2 = "VirtualBox" nocase
        $vm_tool3 = "Hyper-V" nocase
        $vm_tool4 = "VIRTUAL HD" nocase
        $vm_tool5 = "C:\\windows\\system32\\sample_1.exe" 
        $vm_tool6 = "Registry Monitor - Sysinternals: www.sysinternals.com" nocase

    condition:
        all of them
}

rule spam {
    meta:
        description = "Detects spam activity"
        author = "Lee"
        date = "18-08-2025"
        version = "1.0"
    
    strings:
        $spam1 = "Congratulations! You've won a prize!" nocase
        $spam2 = "Click here to claim your reward" nocase
        $spam3 = "Limited time offer" nocase
        $spam4 = "Act now!" nocase
        $spam5 = "Unsubscribe" nocase
        $spam6 = "casino" nocase
        $spam7 = "free gift card" nocase
        $spam8 = "urgent action required" nocase
        $spam9 = "from:" nocase fullword
        $spam10 = "subject:" nocase fullword
        $spam11 = "Dear user," nocase fullword
        $spam12 = "Dear valued customer," nocase fullword

    condition:
        3 of ($spam*)
}


rule sniffer {
    meta: 
        description = "Detects network sniffing activity"
        author = "Lee"
        date = "18-08-2025"
        version = "1.0"

    strings:
        $sniffing_tool = "tcpdump" nocase
        $sniffing_tool2 = "wireshark" nocase
        $sniffing_tool3 = "tshark" nocase
        $sniffing_tool4 = "snort" nocase
        $sniffing_tool5 = "ngrep" nocase
        $sniffing_tool6 = "pcap_open" nocase

    condition:
        any of ($sniffing_tool*) 
}

rule Trojan_Backdoor
{
    meta:
        description = "Detects a generic backdoor trojan"
        author = "Lee"
        date = "19-08-2025"
    
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

rule autorun {
    meta:
        description = "indicates attempt to spread through autorun"
        author = "Lee"
        date = "18-08-2025"
        version = "1.0"
    
    strings:
        $a = "[autorun]" 
        $b = "open="

    condition:
        all of them
}
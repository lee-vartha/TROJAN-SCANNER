rule vmdetect (
    meta: 
        description = "Detects virtual machine activity"
        author = "Lee"
        date = "18-08-2025"
        version = "1.0"

    strings:
        $vm_tool1 = "VMware" nocase
        $vm_tool2 = "VirtualBox" nocase
        $vm_tool3 = "Hyper-V" nocase
        $vm_tool4 = "VIRTUAL HD" no case
        $vm_tool5 = "C:\\windows\\system32\\sample_1.exe" 
        $vm_tool6 = "Registry Monitor - Sysinternals: www.sysinternals.com" nocase

    condition:
        all of them
)
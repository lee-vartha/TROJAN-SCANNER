rule Demo_Trojan {
    meta: 
        description = "Demo concept to detect example trojan behaviour"
        author = "Lee"
    
    strings:
        $s1 = "ThisProgramIsMalicious" ascii nocase
        $s2 = "Trojan" ascii nocase
        $mz = { 4D 5A } // PE file header for windows executables
    
    condition:
    $s1 or $s2 or $mz
}
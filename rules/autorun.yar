rule autorun {
    meta:
        description = "indicates attempt to spread through autorun"
        author = "Lee"
        date = "18-01-2025"
        version = "1.0"
    
    strings:
        $a = "[autorun]" 
        $b = "open="

    condition:
        all of them
}
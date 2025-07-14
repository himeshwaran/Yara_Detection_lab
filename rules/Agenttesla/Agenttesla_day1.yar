
import "pe"

rule Agenttesla_family
{
     meta :
        author= "Himesthehacker"
        description= "Detects .net packed malware"
        data ="2025-07-14"
        verion ="1.0"

    strings:
        $a = "ModernAdapter" ascii nocase  // CompanyName: ModernAdapter
        $b = "iguc.exe" ascii              // OriginalFilename: iguc.exe
        $c = "v4.0.30319" ascii            // Library version
    condition:
        uint16(0) == 0x5A4D and all of ($a,$b,$c)  and 
        pe.imphash()== "f34d5f2d4577ed6d9ceec516c1f5a744" and filesize <1MB and
        pe.sections[0].name == ".text"
}

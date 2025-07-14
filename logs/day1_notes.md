**STATIC ANALYSIS SUMMAY**
TOOLS USER :
   -strings
   -die
   -peframe

**Observations from Static Analysis** ::
While analyzing the sample bf166be918695404ec2724b62671d7eac13fd67e39433894439d70a2ce534861.exe, I performed static analysis using the above tools and found the following Indicators of Compromise (IOCs) and PE structure details:

✅ Extracted IOCs and Metadata:

| Attribute             | Value                            |
| --------------------- | -------------------------------- |
| **Company Name**      | ModernAdapter                    |
| **Internal Filename** | iguc.exe                         |
| **.NET Version**      | v4.0.30319                       |
| **File Type**         | .NET Executable                  |
| **Import Hash**       | f34d5f2d4577ed6d9ceec516c1f5a744 |
| **File Size**         | `< 1MB` (confirmed in scan)      |
| **Entry Point**       | Inside `.text` section           |


** PE Section Details**
| Section | Purpose                     | Notes                            |
| ------- | --------------------------- | -------------------------------- |
| `.text` | Contains executable code    | High entropy > 7.5 → Packed      |


🔐 Packing / Obfuscation
Entropy Check:
Using peframe, the .text section was found to have high entropy (>7.5), which suggests that the sample might be packed or obfuscated.


Tool Detection:
Detect It Easy (DIE) indicated that the sample may be .NET packed, possibly with a custom stub or crypter.


🎯 Why This Matters
These details helped build a YARA rule that targets:
Embedded metadata (company name, filename)

.NET strings

PE header characteristics (MZ header, entropy, import hash)



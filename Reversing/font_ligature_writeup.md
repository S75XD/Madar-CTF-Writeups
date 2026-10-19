# CTF Write-up: Font Ligature

## Challenge Information
* **Challenge Name:** Font Ligature
* **Category:** Reversing
* **Difficulty:** Easy
* **Platform:** Flagyard
* **Author:** Flagyard

## Challenge Overview
**Description:** *"Fonts always hide something."*
The objective of this challenge is to analyze a provided TrueType Font (`.ttf`) file to uncover a hidden flag. The challenge focuses on the internal structures of font files, specifically exploiting Glyph Substitution (GSUB) tables and font ligatures to conceal data.

## Reconnaissance
During the initial inspection of `FlagFont.ttf`, standard font decompilation tools were utilized. Attempting to dump the font's XML representation using FontTools (`ttx FlagFont.ttf`) resulted in an `IndexError: array index out of range`. 

This error was caused by a deliberately malformed `hdmx` (Horizontal Device Metrics) table, planted by the challenge author as an anti-analysis technique to break automated parsers. Recognizing that the flag was likely hidden in the ligatures (as the challenge name suggests), the reconnaissance strategy shifted to bypassing the broken tables and extracting only the `GSUB` table.

## Solution Steps
1. **Bypass Malformed Tables:** To avoid the `hdmx` crash, the `ttx` tool was instructed to extract *only* the Glyph Substitution table using the `-t` parameter.
   ```bash
   ttx -t GSUB FlagFont.ttf
   ```
2. **Analyze the GSUB XML:** Opening the resulting `FlagFont.ttx` file revealed a complex chain of substitution rules (`<ChainContextSubst>`).
3. **Trace the Ligature State Machine:** The font uses a state-machine-like structure. It starts expecting the letter `F`, which it substitutes with a temporary internal glyph. If the next inputted character is `l`, it substitutes both with another glyph, and so on. 
4. **Extract the Sequence:** By following the `<InputCoverage>` tags within the chain sequentially, the required keystrokes to trigger the final ligature were exposed. The sequence started with `F`, `l`, `a`, `g`, `Y`, `braceleft`.
5. **Decode the Payload:** The inner string consisted of standard characters and spelled-out numbers (e.g., `<Glyph value="four"/>`, `<Glyph value="five"/>`, `<Glyph value="a"/>`). Mapping these spelled-out names to their numeric equivalents (`4`, `5`, `a`) reconstructed the MD5-like string inside the flag format.
6. **Identify the Trap:** The analysis showed that closing the curly brace (`braceright`) prematurely directed the font to a trap glyph (`glyph04690`), whereas completing the full correct sequence directed it to the actual flag glyph (`glyph04689`).

## Flag
`FlagY{45ae3494b8ed953bbc1707116566e977}`

## Root Cause & Lessons Learned
* **Technique / Root Cause:** The vulnerability or "trick" relies on the legitimate typographical feature of ligatures (GSUB tables). By creating an excessively long chain of context substitutions, an author can effectively hardcode a secret string (the flag) directly into the font's rendering logic. Additionally, tampering with standard font tables (`hdmx`) is a common anti-reversing tactic used to hinder standard tooling.
* **Lessons Learned:** Automated reverse engineering tools can be easily disrupted by malformed headers or non-essential corrupted tables. When facing decompilation errors, isolating the specific components required for the analysis (like isolating the GSUB table) or using programmable libraries with error-ignoring capabilities (like `fontTools` in Python) is a highly effective workaround.

***

### Automated Extraction Script (Python)
Here is a Python script utilizing `fontTools` and `re` to automatically bypass the broken `hdmx` table, dump the `GSUB` table, and parse the sequence to print the flag.

```python
import re
import os
from fontTools.ttLib import TTFont

def extract_ligature_flag(file_path):
    print(f"[*] Loading font: {file_path}")
    
    # Load the font, explicitly ignoring intentionally corrupted tables (like hdmx)
    try:
        font = TTFont(file_path, ignoreDecompileErrors=True)
    except Exception as e:
        print(f"[-] Failed to load font: {e}")
        return

    if 'GSUB' not in font:
        print("[-] No GSUB (Glyph Substitution) table found.")
        return
        
    print("[*] Extracting GSUB data...")
    temp_xml = 'temp_gsub.xml'
    font.saveXML(temp_xml, tables=['GSUB'])
    
    # Mapping table for the spelled-out numbers and symbols used in the font
    num_map = {
        'zero': '0', 'one': '1', 'two': '2', 'three': '3', 'four': '4',
        'five': '5', 'six': '6', 'seven': '7', 'eight': '8', 'nine': '9',
        'braceleft': '{', 'braceright': '}'
    }
    
    flag = "F" # Starts with F as per the first ContextSubst
    
    try:
        with open(temp_xml, 'r') as f:
            content = f.read()
            
            # Find all InputCoverage glyphs representing the required keystrokes
            matches = re.findall(r'<InputCoverage.*?>\s*<Glyph value="(.*?)"/>', content)
            
            for match in matches:
                if match in num_map:
                    flag += num_map[match]
                elif len(match) == 1: 
                    # Standard single characters like 'l', 'a', 'g', 'Y', 'a', 'e'
                    flag += match
                    
        # The chain contains repeated 'braceright' for trap states.
        # We isolate the exact sequence leading up to the first valid closure.
        final_flag = flag.split('}')[0] + '}'
        
        print(f"[+] Extracted Flag: {final_flag}")
        
    finally:
        # Clean up the temporary XML file
        if os.path.exists(temp_xml):
            os.remove(temp_xml)

if __name__ == "__main__":
    # Ensure the TTF file is in the same directory or provide the full path
    extract_ligature_flag('FlagFont.ttf')
```
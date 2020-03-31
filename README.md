# OWASP Firmware Security Testing Methodology

The Firmware Security Testing Methodology \(FSTM\) is composed of nine stages tailored to enable security researchers, software developers, consultants, hobbyists, and Information Security professionals with conducting firmware security assessments.

| **Stage** | **Description** |
| :--- | :--- |
| 1. Information gathering and reconnaissance | Acquire all relative technical and documentation details pertaining to the target device's firmware |
| 2. Obtaining firmware | Attain firmware using one or more of the proposed methods listed |
| 3. Analyzing firmware | Examine the target firmware's characteristics |
| 4. Extracting the filesystem | Carve filesystem contents from the target firmware |
| 5. Analyzing filesystem contents | Statically analyze extracted filesystem configuration files and binaries for vulnerabilities |
| 6. Emulating firmware | Emulate firmware files and components |
| 7. Dynamic analysis | Perform dynamic security testing against firmware and application interfaces |
| 8. Runtime analysis | Analyze compiled binaries during device runtime |
| 9. Binary Exploitation | Exploit identified vulnerabilities discovered in previous stages to attain root and/or code execution |

The full methodology is available for download in the [release](https://github.com/scriptingxss/owasp-fstm/releases) section of this repository. Consider visiting the [OWASP Internet of Things Project](https://www.owasp.org/index.php/OWASP_Internet_of_Things_Project) wiki page for the latest methodology updates and forthcoming project releases.

A preconfigured Ubuntu virtual machine \(_EmbedOS_\) with firmware testing tools used throughout the methodology can be downloaded via the following [\[link\]](https://tinyurl.com/EmbedOS-2019). Details regarding EmbedOS' tools can be found on GitHub [https://github.com/scriptingxss/EmbedOS](https://github.com/scriptingxss/EmbedOS).


# CookieRun DJBF Converter - Python Version

A ~~Windows only~~ cross-platform CLI tool for encrypting and decrypting Cookie Run Kakao/QQ's DJBF files. 

Place this executable in a folder and run with the appropriate commands. It will run through all files within the current folder (that fit the search pattern if provided) and convert them.  Decrypted files will be output with a `.bin` extension and encrypted with a `.djb` extension.

**NOTE** this tool will attempt to run on all files within a folder ~~and does not validate if each files needs to or can be converted so will crash on invalid files. Additionally, output files will overwrite files of the same name.~~ and output as `.bin` if `-o/--output` not given

`python cookie_run_djbf_converter.py -m decrypt -k kakao -i Game.djb`  
`python cookie_run_djbf_converter.py -m encrypt -k kakao -v 1 -f "AES_ECB, FastLZ" -i Game.djb`

#### Arguments
| Short Name | Long Name | Description | Required
| ---- | ---- | ---- | :---- |
| -i | \--input | Input file | Yes
| -o | \--output | Output file | No
| -m | \--mode | Encrypt or Decrypt | Yes
| -k | \--key | Encryption key to use. Kakao or QQ | Yes
|    | \--keyfile | Custom Encryption key to use. Self-made. | No, but give it a try :)
|    | \--ignore-checksum | Ignore checksum verification error. | No, send issues only.
| -d | \--debug | Enable debug output. | No, send issues only.
| -v | \--version | Output file minor version. 0, 1, 2 or 3 | When Encrypting
| -f | \--flags | Output file encryption and compression methods |  When Encrypting
| -s | \--searchPattern | Filename filter | No
| -h | \--help | Shows this table | When you lack of braincells |

#### Version

The above version refers to the minor version of the format which is the second byte of the version field. The major version is always 1 and is handled by the application. E.g.  [major: 1, minor: 3] = 0x0103 in hex and 259 in decimal when viewing a file in the hex editor.

#### Flags

Each version supports separate flags. The application does it's best to correct the flags based on the version provided however AES_ECB and AES_CBC are exclusive so cannot be used simultaneously.

When encrypting with multiple flags, the values need to be comma separated e.g. "AES_ECB, FastLZ".

| Flag | Value | Meaning | Supported Versions
| ---- | ---- |---- | :---- |
| AES_ECB | 0x1 |AES encryption in ECB mode | 0+
| AES_CBC | 0x2 | AES encryption in CBC mode | 2+
| FastLZ | 0x80 |FastLZ - a variant of LZ77 compression   | 1+

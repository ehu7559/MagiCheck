# MagiCheck
Magic Byte Checker utility. Helps prevent phishing attacks!

This lightweight utility measure was developed over the course of a single day.

USAGE:
python3 [options] [directory]

The program will explore one's computer for files which do not match their
extensions.

OPTIONS:
-r              Recursion Desired. Will recursively scan subdirectories.

--no-warning    Suppresses "WARNING" type messages

--no-failure    Suppresses "FAILURE" messages. Rather pointless, but who cares?

-q or --quiet   Suppresses "SUCCESS" and "WARNING" messages

-v or --verbose Shows "SUCCESS" messages

-1137h4x0rz     "Hacker Mode", with a short delay between prints to look cool!

DEPENDENCIES:
This utility uses the python-magic library. It can be removed with little to no
impact on core functionality.

PLANNED UPDATES:
- Finish adding signatures from Wikipedia's list
    https://en.wikipedia.org/wiki/List_of_file_signatures
- Add some quality of life improvements
    - Will likely convert it to a Cython program.
- Add some detection using MIME types (?)
- Working to filter out raw text files (such as source code) from warnings, as 
    they currently cause warning statements.
- Speed optimizations and compactness modifications.
- Move signature list to external file.
    - Considering moving to customizable signature list files
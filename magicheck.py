#!/usr/bin/python3

#MAGIC BYTE CHECKER
#Lightweight phishing provention
import sys
from os import listdir
from os.path import isfile, isdir, join
from magic import from_file
from time import sleep

#CONSTANTS:
RECURSION = False
CAUTIOUS = False
NO_WARN = False
NO_OKAY = True
NO_FAIL = False
HACKERLOOK = False
TIMEDELAY = 0.25
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def warn(statement):
    if HACKERLOOK:
        sleep(TIMEDELAY)
    if not NO_WARN:
        print(bcolors.WARNING + "WARNING: \t" + statement + bcolors.ENDC)

def fail(statement):
    if HACKERLOOK:
        sleep(TIMEDELAY)
    if not NO_FAIL:
        print(bcolors.FAIL + "FAILURE: \t"+ statement + bcolors.ENDC)

def okay(statement):
    if HACKERLOOK:
        sleep(TIMEDELAY)
    if not NO_OKAY:
        print(bcolors.OKGREEN + "SUCCESS: \t" + statement + bcolors.ENDC)


################################################################################
#SIGNATURE CLASS AND LIST
################################################################################
class sig:
    def __init__(self, magichex, offsethex, description="[none]"):
        self.magicbytes = magichex.lower().split(" ")
        self.offset = int(str(offsethex), 16)
        self.text = description

extLookUp = {}

def addsig(ext, magichex, offsethex=0, label="[none]"):
    if not (ext.lower() in extLookUp.keys()):
        extLookUp[ext.lower()] = []
    extLookUp[ext.lower()].append(sig(magichex,offsethex,label))

addsig("", "23 21", 0, "Script or data to be passed to the program following the shebang (#!)")
addsig("pcap", "D4 C3 B2 A1", 0, "Libpcap File Format (little endian)")
addsig("pcap", "A1 B2 C3 D4", 0, "Libpcap File Format (big endian)")
addsig("pcap", "4D 3C B2 A1", 0, "Libpcap File Format (nanosecond-resolution) (little endian)")
addsig("pcap", "A1 B2 3C 4D", 0, "Libpcap File Format (nanosecond-resolution) (big endian)")
addsig("pcapng","0A 0D 0D 0A", 0, "PCAP Next Generation Dump File Format")
addsig("rpm", "ED AB EE DB", 0, "RedHat Package Manager (RPM) package")
addsig("sqlitedb", "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00", 0, "SQLite Database")
addsig("sqlite", "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00", 0, "SQLite Database")
addsig("db", "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00", 0, "SQLite Database")
addsig("bin", "53 50 30 31", 0, "Amazon Kindle Update Package")
addsig("pic", "00", 0, "IBM Storyboard bitmap file/Windows Program Information File/Mac Stuffit Self-Extracting Archive/IRIS OCR data file")
addsig("pif", "00", 0, "IBM Storyboard bitmap file/Windows Program Information File/Mac Stuffit Self-Extracting Archive/IRIS OCR data file")
addsig("sea", "00", 0, "IBM Storyboard bitmap file/Windows Program Information File/Mac Stuffit Self-Extracting Archive/IRIS OCR data file")
addsig("ytr", "00", 0, "IBM Storyboard bitmap file/Windows Program Information File/Mac Stuffit Self-Extracting Archive/IRIS OCR data file")
addsig("pdb", "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", 11, "PalmPilot Database/Document File")
addsig("DBA", "BE BA FE CA", 0, "Palm Desktop Calendar Archive")
addsig("dba", "00 01 42 44", 0, "Palm Desktop To Do Archive")
addsig("TDA", "00 01 44 54", 0, "Palm Desktop Calendar Archive")
addsig("TDF$", "54 44 46 24", 0, "Telegram Desktop File")
addsig("tdef", "54 44 45 46", 0, "Telegram Desktop Encrypted File")
addsig("", "00 01 00 00", 0, "Palm Desktop Data File (Access format)")
addsig("ico", "00 00 01 00", 0, "Computer icon encoded in ICO file format")
addsig("icns", "69 63 6e 73", 0, "Apple Icon Image format")
addsig("3gp", "66 74 79 70 33 67", 4, "3rd Generation Partnership Project 3GPP multimedia file")
addsig("3g2", "66 74 79 70 33 67", 4, "3rd Generation Partnership Project 3GPP multimedia file")
addsig("z", "1F 9D", 0, "compressed file (often tar zip) using Lempel-Ziv-Welch algorithm")
addsig("tar.z", "1F 9D", 0, "1F")
addsig("z", "1F A0", 0, "Compressed file (often tar zip) using LZH algorithm")
addsig("tar.z", "1F A0", 0, "Compressed file (often tar zip) using LZH algorithm")
addsig("bac", "42 41 43 4B 4D 49 4B 45 44 49 53 4B", 0, "AmiBack Amiga Backup data file")
addsig("idx", "49 4E 44 58", 0, "AmiBack Amiga Backup index file")
addsig("plist", "62 70 6C 69 73 74", 0, "Binary Property List file")
addsig("bz2", "42 5A 68", 0, "Compressed file using Bzip2 algorithm")
addsig("gif", "47 49 46 38 37 61", 0, "Graphics Interchange Format, 87a")
addsig("gif", "47 49 46 38 39 61", 0, "Graphics Interchange Format, 89a")
addsig("tif", "49 49 2A 00", 0, "Tagged Image File Format (TIFF)")
addsig("tiff", "49 49 2A 00", 0, "Tagged Image File Format (TIFF)")
addsig("tif", "4D 4D 00 2A", 0, "Tagged Image File Format (TIFF)")
addsig("tiff", "4D 4D 00 2A", 0, "Tagged Image File Format (TIFF)")
addsig("cr2", "49 49 2A 00 10 00 00 00 43 52", 0, "Canon RAW Format Version 2 (based on TIFF)")
addsig("cin", "80 2A 5F D7", 0, "Kodak Cineon image")
addsig("", "52 4E 43 01", 0, "Compressed file using Rob Northen Compression algorithm, v1")
addsig("", "52 4E 43 02", 0, "Compressed file using Rob Northen Compression algorithm, v2")
addsig("nui", "4E 55 52 55 49 4D 47", 0, "nuru ASCII/ANSI image file")
addsig("nup", "4E 55 52 55 50 41 4C", 0, "nuru ASCII/ANSI palette file")
addsig("exr", "76 2F 31 01", 0, "OpenEXR image")
addsig("bpg", "42 50 47 FB", 0, "Better Portable Graphics format")
addsig("jpg", "FF D8 FF E0 00 10 4A 46 49 46 00 01", 0, "JPEG file")
addsig("jpeg", "FF D8 FF E0 00 10 4A 46 49 46 00 01", 0, "JPEG file")
addsig("jpg", "FF D8 FF DB", 0, "JPEG file")
addsig("jpeg", "FF D8 FF DB", 0, "JPEG file")
addsig("jpg", "FF D8 FF EE", 0, "JPEG file")
addsig("jpeg", "FF D8 FF EE", 0, "JPEG file")
addsig("jpg", "FF D8 FF E1", 0, "JPEG file")
addsig("jpeg", "FF D8 FF E1", 0, "JPEG file")



################################################################################
#                               END SIGNATURE LIST                             #
################################################################################
def crawlpath(dirpath):
    
    #list all files
    fileshere = [f for f in listdir(dirpath) if isfile(join(dirpath, f))]
    #check each file

    for f in fileshere:
        fpath = join(dirpath, f)
        result = checkbytes(fpath)
        if result == "MATCH":
            okay(fpath)
        elif result == "MISMATCH":
            fail(fpath)
            print(bcolors.FAIL + "DETECTED: \t" + from_file(fpath) + bcolors.ENDC)
        else:
            warn(fpath)  
    #list all directories
    if RECURSION:
        dirshere = [d for d in listdir(dirpath) if isdir(join(dirpath, d))]
        #check each directory
        for d in dirshere:
            crawlpath(join(dirpath,d))
    return

def checkbytes(filepath):
    '''checks the magic bytes of the file for agreements with its extension'''
    
    # get its extension
    ext = filepath.split(".")[-1].lower()
    if not(ext in extLookUp.keys()):
        return "UNKNOWN"

    for asig in extLookUp[ext]:
        if(checksig(filepath, asig)):
            return "MATCH"
    
    if (not CAUTIOUS) and (ext == ""):
        return "UNKNOWN"

    #return agreement
    return "MISMATCH" 

def checksig(filepath, signature):
    f = open(filepath, "rb")
    f.seek(signature.offset)
    siglen = len(signature.magicbytes)

    #Read bytes
    buf = bytearray(f.read(siglen))
    
    #Check signature
    for i in range(siglen):
        if signature.magicbytes[i] == "??":
            continue
        if not int(str(signature.magicbytes[i]), 16) == buf[i]:
            f.close()
            return False
    f.close()
    return True
    
#Main
if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("INSUFFICIENT ARGUMENTS")
    else:
        if "-r" in sys.argv:
            RECURSION = True
        if "--no-warning" in sys.argv:
            NO_WARN = True
        if "--no-failure" in sys.argv:
            NO_FAIL = True
        if "-q" in sys.argv or "--quiet" in sys.argv:
            NO_OKAY = True
            NO_WARN = True
        if "-v" in sys.argv or "--verbose" in sys.argv:
            NO_OKAY = False
        if "--1337h4x0rz" in sys.argv:
            HACKERLOOK = True
        crawlpath(sys.argv[-1])
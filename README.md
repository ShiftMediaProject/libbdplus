# libbdplus

**libbdplus** is a research project for a cross-platform open-source implementation of the BD+ VM system.

# Disclaimer

This library is written for the purpose of playing Blu-ray movies.

It is intended for software that want to support Blu-ray playback (such as VLC and
MPlayer). We, the authors of this library, do not condone nor endorse piracy.

This library is simply a tool for playback of Blu-ray movies. Like any tool, the
use of this tool can also be abused. There are already numerous laws in
different countries and juridictions all over the world that protect copyrighted
material, such as Blu-ray movies.

With that said, it would have been impossible for us to distribute this library
with terms such as "you cannot use this library for piracy", because this would
violate the Open Source Definition and the LGPL license.
Instead, we present to everyone this disclaimer.

As a reminder, here is also the disclaimer found at the beginning of any movie
in relation to copyrights.

## ATTENTION

International agreement and national laws protect copyrighted motion pictures,
videotapes, and sound recordings.

UNAUTHORIZED REPRODUCTION, EXHIBITION OR DISTRIBUTION OF COPYRIGHTED MOTION
PICTURES CAN RESULT IN SEVERE CRIMINAL AND CIVIL PENALTIES UNDER THE LAWS OF
YOUR COUNTRY.

The International Criminal Police Organization - INTERPOL, has expressed its
concern about motion picture and sound recording piracy to all of its member
national police forces. (Resolution adopted at INTERPOL General Assembly,
Stockholm, Sweden, September 8, 1977.)

# Contribute

To contribute, just compile the library and open merge requests on the repository:
https://code.videolan.org/videolan/libbdplus

## CoC

The [VideoLAN Code of Conduct](https://wiki.videolan.org/CoC) applies to this project.

## CLA

There is no CLA.

People will keep their copyright and their authorship rights, while adhering to the license.

VideoLAN will only have the collective work rights.





# Welcome to the BD+ library

This library is not complete, in that it will never be complete and
will always require updates to stay up to date with the latest Bluray
disks released.

The general flow on this library is that the higher level 'player'
code will call us if there exist a "BDSVM/00000.svm" file on the disk. If
this is the case it will call bdplus_init(), connect the library with
other parts of BluRay player and call bdplus_start().

BD+ VM executes the DLX assembled code inside the SVM file.
This will perform thousands of AES, SHA, file reads and detailed
memory checks to guess the authenticity of the player.

If all goes well, the SVM will eventually spit out a 'conversion
table'. This is a large table (usually about 1-2MB but it varies) which
contains offsets into the M2TS video file. (usually the main title).

The video file has been purposely corrupted at random places. These
offsets, and 12 bytes of data for each one, is used to repair the
video file.

However, the conversion table is also 'encoded' (XOR). So the VM is
further executed to ask for the decode-keys for each part (segment) of
the conversion table.

============================================

the BD+ library will need various keys to perform its task. More
precisely, it needs:

6 AES Player keys (each 16 bytes)

There are also 5 dumps of the Player Discovery replies.

There is player memory dumps that needs to be simulated. Including
player name, version and executable map.

Configuration directory (vm0) is searched from following places:

  Linux (xdg specification):
    /etc/xdg/bdplus/
    $HOME/.config/bdplus/

  Windows:
    %APPDATA%/bdplus/

  Mac OS:
    ~/Library/Preferences/bdplus/

Configuration data is not included with libbdplus.

============================================

The BD+ design also uses 'slots', that is like a save-file stored on
NVRam/USB-Stick or similar permanent storage. The slot layout is 500
slots of 256 bytes each.  The SVM can request a new/free slot to
write, or look for one previously written. In here it can store
information for future play attempts.

Slots are stored in the following file:

  Linux (xdg specification):
    $HOME/.cache/bdplus/slots.bin

  Windows:
    %APPDATA%/bdplus/slots.bin

  Mac OS:
    ~/Library/Caches/bdplus/


============================================

The SVM also communicates with BluRay player BDJ and HDMV subsystems,
using the PSR102, PSR103 and PSR104 registers. To set up callback
functions for communication, BluRay player calls bdplus_set_psr().

============================================

What if things go wrong? And they will! Each new disk brought out will
potentially expose new issues with libbdplus. There are things that
can be done to help fix libbdplus.

You can set environment variables:

 DBG_BDPLUS : General BDPlus debugging, traps etc.

where you can watch the SVM perform its various tasks. It is quite
hard to know where it goes wrong, unless you have something to compare
against though. I don't know if we can record traps and breaks anymore...

 DBG_DLX: In-depth DLX assembly instruction debugging.

This is very verbose and shows the DLX instructions executing. It
would be unlikely to be bugs in the DLX opcodes, but you never
know. Included for amusements sake.


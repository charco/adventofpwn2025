# Challenge 11

## Description

```
🎅🎄 A Surprise From the Bottom of Santa’s Bag… ✨
While Santa was unloading gifts this year, something thumped at the very bottom of his Christmas bag.
After brushing off a blizzard of stale cookie crumbs ❄️🍪, he discovered…

🖥️ A BRAND NEW COMPUTER! 💾
(Brand new… in 1994, that is.)

It comes with a stack of vintage floppy disks, a power brick that absolutely should not be this warm 🔌🔥, and a handwritten North Pole Tech Support card that simply reads:

“Good luck setting it up! Ho-ho-retro!”

So fire up that beige box, pop in a floppy or three, and prepare yourself—
because nothing says Happy Holidays like convincing 30-year-old hardware to connect to the network! 🎁

When things inevitably go sideways, don’t panic—
📞 NORTH POLE TECH SUPPORT: 1-800-242-8478
🧝‍♂️🔧 North Pole elves are standing by to assist you with any tech-support needs.
Seriously. Call them. They'd be happy to help; just let them know what you're seeing.

Once you’ve got the system up and running—and after you’ve battled the screeching modem 📡 to get online—
🎁 connect to 192.168.13.37 on port 1337 to earn your flag.

NOTE: This challenge requires a GUI to interact with the vintage computer, and so must be accessed through the desktop interface.
```

## Analysis

This challenge is old-school. You start with a VM and you can interact with it
via the serial console or the graphical interface.

Via the serial console you have the following options:

* Load: loads a floppy disk from a preset of available disks.
* Paste and Paste-Home: Paste the clipboard into the VM as send-keys.
* Eject: Ejects the floppy disk.
* Snapshot: Takes a snapshot of the hard-drive.
* Reboot: Reboots the VM.
* Quit: Shutdowns the VM.

The launch script provides some extra background: there's a telnet server
listening on ip `192.168.13.37` on port `1337` in a network namespace available
inside the VM. This means that we need to be able to reach it from inside the
VM.

The VM has a disk to install MS-DOS 6.22 and we can start from there.

We can start by loading the MS-DOS disk 1 and rebooting the VM, then we can click
on the VM window and follow the installation, switching disks when required.

Note that we can do everything from the serial console with the sendkeys
commands, but that is more tedious.

The setup will ask to insert disk 2 and 3, and then eject them after all is
done and reboot.

Once in MS-DOS we can do a bunch of stuff, but we don't have any driver
installed not networking setup. Let's load the `pcnet` disk.

```
C:\> DIR /W A:
... PKTDRVR
C:\> DIR /W A:\PKTDRVR
... PCNTPK.COM
C:\> A:\PKTDRVR\PCNTPK INT=0x60
Packet driver for an PCNTPK, version 03.10
Packet driver skeleton copyright 1988-92 ...

Packet driver is at segment 0BBF
Interrupt number 0xB (11)
I/O port 0xC000 (49152)
My ethernet address is 52:54:00:12:34:56
```

You can see that the mac address matches the `launch` script in QEMU.

Now we can load the `MTCP` disk and use `TELNET`.

First we need to create a network configuration file with the `EDIT` command.


```
C:\> EDIT C:\TCP.CFG
```

And these contents (you can use the PASTE command to send them)
```
PACKETINT 0x60
IPADDR    192.168.13.38
NETMASK   255.255.255.0
GATEWAY   192.168.13.1
NAMESERVER 8.8.8.8
```

Set the environment variable for `MTCP`:

```
C:\> SET MTCPCFG=C:\TCP.CFG
```

And now we can run `PING` and `TELNET`:

```
C:\> A:\PING 192.168.13.37
...
Packet sequence number 0 received from 192.168.13.37 in 1.70 ms, ttl=64
...
C:\A A:\TELNET 192.168.13.37 1337
Resolving server address - press [ESC] to abort

Server 192.168.13.37 resolved to 192.168.13.37
Connecting to port 1337

Remember to use Alt-H for help!

Connected to 192.168.13.37 (192.168.13.37) on port 1337

pwn.college{practice}

Connection closed - have a great day!
```

# beacondump
Quickly glance at 802.11 beacon frames

# Compiling on the MacOS

	ayourtch@MAC beacondump % make
	gcc -o beacondump beacondump.c -lpcap
	beacondump.c:262:11: warning: 'pcap_lookupdev' is deprecated: use 'pcap_findalldevs' and use the first device [-Wdeprecated-declarations]
	    dev = pcap_lookupdev(errbuf);
		  ^
	/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/pcap/pcap.h:398:1: note: 'pcap_lookupdev' has been explicitly marked deprecated here
	PCAP_DEPRECATED(pcap_lookupdev, "use 'pcap_findalldevs' and use the first device");
	^
	/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/pcap/funcattrs.h:293:53: note: expanded from macro 'PCAP_DEPRECATED'
	  #define PCAP_DEPRECATED(func, msg)    __attribute__((deprecated(msg)))
							       ^
	1 warning generated.
	ayourtch@MAC beacondump % 


# What it does

It somewhat pretty-prints the essential information about the 802.11 beacon frames,
in a one line per frame format - allowing easy manipulation with grep & other CLI utilities

Either run it without any arguments, and it will print you all beacon frames on the default interface,
or supply the interface to listen on as the first argument and optionally the list of the "friendly"/uninteresting SSIDs.

Here's some example output:

    ayourtch@MAC beacondump % ./beacondump en0 CiscoLive eduroam OpenRoaming CiscoLive-WPA3 CL-NOC
    1675716918172093 channel   36 signal: -93 noise: -97 BSS bcaabbccddb4 | CHEFSTABLE
    1675716919403582 channel   36 signal: -92 noise: -97 BSS bcaabbccddb4 | CHEFSTABLE
    1675716919602664 channel   36 signal: -93 noise: -97 BSS bcaabbccddb4 | CHEFSTABLE
    1675716920225312 channel   36 signal: -92 noise: -97 BSS bcaabbccddb4 | CHEFSTABLE
    1675716920935598 channel   36 signal: -92 noise: -97 BSS bcaabbccddb4 | CHEFSTABLE
    1675716921350881 channel   36 signal: -92 noise: -97 BSS bcaabbccddb4 | CHEFSTABLE
    1675716921450246 channel   36 signal: -92 noise: -97 BSS bcaabbccddb4 | CHEFSTABLE
    1675716921549561 channel   36 signal: -92 noise: -97 BSS bcaabbccddb4 | CHEFSTABLE
    ^C

The first column is a 64-bit timestamp, then the length of the packet, then the frequency
and the rate the beacon is sent at, then signal and noise in dBm, then BSSID, then the SSID.

# Caveats

It's a quick hack I wrote over a course of a few hours, so I made quite some big shortcuts
when parsing the headers. This can probably easily break. Also - I've tested it only on OS X
so far, though in principle there's no reason it should not work on Linux.


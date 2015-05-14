# beacondump
Quickly glance at 802.11 beacon frames

This is a quick first prototype, to see if it's useful in practice.

# What it does

It somewhat pretty-prints the essential information about the 802.11 beacon frames,
in a one line per frame format - allowing easy manipulation with grep & other CLI utilities

Here's some example output:

    1431614537564168 len 231   freq 5200 rate 6000  s/n: -45 -90 BSS 0016b6aaaaaa | HappyHouse5
    1431614537661598 len 231   freq 5200 rate 6000  s/n: -46 -90 BSS 0016b6aaaaaa | HappyHouse5
    1431614537771185 len 231   freq 5200 rate 6000  s/n: -45 -90 BSS 0016b6aaaaaa | HappyHouse5
    1431614537867200 len 231   freq 5200 rate 6000  s/n: -44 -90 BSS 0016b6aaaaaa | HappyHouse5
    1431614537976091 len 231   freq 5200 rate 6000  s/n: -45 -90 BSS 0016b6aaaaaa | HappyHouse5
    1431614538075445 len 231   freq 5200 rate 6000  s/n: -46 -90 BSS 0016b6aaaaaa | HappyHouse5
    1431614538174928 len 231   freq 5200 rate 6000  s/n: -45 -90 BSS 0016b6aaaaaa | HappyHouse5

The first column is a 64-bit timestamp, then the length of the packet, then the frequency
and the rate the beacon is sent at, then signal and noise in dBm, then BSSID, then the SSID.

# Caveats

It's a quick hack I wrote over a course of a few hours, so I made quite some big shortcuts
when parsing the headers. This can probably easily break. Also - I've tested it only on OS X
so far, though in principle there's no reason it should not work on Linux.


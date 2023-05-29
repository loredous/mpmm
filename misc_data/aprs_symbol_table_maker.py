import re

rex = r'\/(.) (\w\w)([Vz]) (\d\d) (.*) ?\\(.) (\w\w)([Vz]) (\d\d) ?(.*)'

raw_table = r"""/! BBV 01 Police, Sheriff \! OBV 01 Emergency
/" BCV 02 [reserved] \" OCV 02 [reserved]
/# BDV 03 Digi (green star with white center) \# ODz 03 Digi (green star) [with overlay]
/$ BEV 04 Phone \$ OEV 04 Bank or ATM (green box)
/% BFV 05 DX Cluster \% OFV 05
/& BGV 06 HF Gateway \& OGz 06 HF Gateway (diamond) [w/ overlay]
/’ BHV 07 Small Aircraft (SSID –7) \’ OHV 07 Crash Site
/( BIV 08 Mobile Satellite Groundstation \( OIV 08 Cloudy
/) BJV 09 \) OJV 09
/* BKV 10 Snowmobile \* OKV 10 Snow
/+ BLV 11 Red Cross \+ OLV 11 Church
/, BMV 12 Boy Scouts \, OMV 12 Girl Scouts
/- BNV 13 House QTH (VHF) \- ONV 13 House (HF)
/. BOV 14 X \. OOV 14 Unknown/indeterminate position
// BPV 15 Dot \/ OPV 15
/0 P0V 16 Numerical Circle 0 Obsolete. \0 A0z 16 Circle [with overlay]
/1 P1V 17 Numerical Circle 1 Obsolete. \1 A1V 17
/2 P2V 18 Numerical Circle 2 Obsolete. \2 A2V 18
/3 P3V 19 Numerical Circle 3 Obsolete. \3 A3V 19
/4 P4V 20 Numerical Circle 4 Obsolete. \4 A4V 20
/5 P5V 21 Numerical Circle 5 Obsolete. \5 A5V 21
/6 P6V 22 Numerical Circle 6 Obsolete. \6 A6V 22
/7 P7V 23 Numerical Circle 7 Obsolete. \7 A7V 23
/8 P8V 24 Numerical Circle 8 Obsolete. \8 A8V 24
/9 P9V 25 Numerical Circle 9 Obsolete. \9 A9V 25 Gas Station (blue pump)
/: MRV 26 Fire \: NRV 26 Hail
/; MSV 27 Campground \; NSV 27 Park/Picnic Area
/< MTV 28 Motorcycle (SSID –10) \< NTV 28 NWS Advisory (gale flag)
/= MUV 29 Railroad Engine \= NUV 29
/> MVV 30 Car (SSID –9) \> NVz 30 Car [with overlay]
/? MWV 31 File Server \? NWV 31 Information Kiosk (blue box with ?)
/@ MXV 32 Hurricane Future Prediction (dot) \@ NXV 32 Hurricane/Tropical Storm
/A PAV 33 Aid Station \A AAz 33 Box [with overlay]
/B PBV 34 BBS \B ABV 34 Blowing Snow
/C PCV 35 Canoe \C ACV 35 Coastguard
/D PDV 36 \D ADV 36 Drizzle
/E PEV 37 Eyeball (eye catcher) \E AEV 37 Smoke
/F PFV 38 \F AFV 38 Freezing Rain
/G PGV 39 Grid Square (6-character) \G AGV 39 Snow Shower
/H PHV 40 Hotel (blue bed icon) \H AHV 40 Haze
/I PIV 41 TCP/IP \I AIV 41 Rain Shower
/J PJV 42 \J AJV 42 Lightning
/K PKV 43 School \K AKV 43 Kenwood
/L PLV 44 \L ALV 44 Lighthouse
/M PMV 45 MacAPRS \M AMV 45
/N PNV 46 NTS Station \N ANV 46 Navigation Buoy
/O POV 47 Balloon (SSID –11) \O AOV 47
/P PPV 48 Police \P APV 48 Parking
/Q PQV 49 \Q AQV 49 Earthquake
/R PRV 50 Recreational Vehicle (SSID –13) \R ARV 50 Restaurant
/S PSV 51 Space Shuttle \S ASV 51 Satellite/PACsat
/T PTV 52 SSTV \T ATV 52 Thunderstorm
/U PUV 53 Bus (SSID –2) \U AUV 53 Sunny
/V PVV 54 ATV \V AVV 54 VORTAC Nav Aid
/W PWV 55 National Weather Service Site \W AWz 55 NWS Site [with overlay]
/X PXV 56 Helicopter (SSID –6) \X AXV 56 Pharmacy Rx
/Y PYV 57 Yacht (sail boat) (SSID –5) \Y AYV 57
/Z PZV 58 WinAPRS \Z AZV 58
/[ HSV 59 Jogger \[ DSV 59 Wall Cloud
/\ HTV 60 Triangle (DF) \\ DTV 60
/] HUV 61 PBBS \] DUV 61
/^ HVV 62 Large Aircraft \^ DVz 62 Aircraft [with overlay]
/_ HWV 63 Weather Station (blue) \_ DWz 63 WX Stn with digi (green) [w/ ov’lay]
/‘ HXV 64 Dish Antenna \‘ DXV 64 Rain
/a LAV 65 Ambulance (SSID –1) \a SAz 65 (A=ARRL, R=RACES etc) [w/ ov’lay
/b LBV 66 Bicycle (SSID –4) \b SBV 66 Blowing Dust/Sand
/c LCV 67 \c SCz 67 Civil Defense (RACES) [w/ overlay]
/d LDV 68 Dual Garage (Fire Department) \d SDV 68 DX Spot (from callsign prefix)
/e LEV 69 Horse (equestrian) \e SEV 69 Sleet
/f LFV 70 Fire Truck (SSID –3) \f SFV 70 Funnel Cloud
/g LGV 71 Glider \g SGV 71 Gale Flags
/h LHV 72 Hospital \h SHV 72 Ham Store
/i LIV 73 IOTA (Island on the Air) \i SIz 73 Indoor short range digi [w/ overlay]
/j LJV 74 Jeep (SSID –12) \j SJV 74 Work Zone (steam shovel)
/k LKV 75 Truck (SSID –14) \k SKV 75
/l LLV 76 \l SLV 76 Area Symbols (box, circle, etc)
/m LMV 77 Mic-repeater \m SMV 77 Value Signpost {3-char display}
/n LNV 78 Node \n SNz 78 Triangle [with overlay]
/o LOV 79 Emergency Operations Center \o SOV 79 Small Circle
/p LPV 80 Rover (puppy dog) \p SPV 80 Partly Cloudy
/q LQV 81 Grid Square shown above 128m \q SQV 81
/r LRV 82 Antenna \r SRV 82 Restrooms
/s LSV 83 Ship (power boat) (SSID –8) \s SSz 83 Ship/Boat (top view) [with overlay]
/t LTV 84 Truck Stop \t STV 84 Tornado
/u LUV 85 Truck (18-wheeler) \u SUz 85 Truck [with overlay]
/v LVV 86 Van (SSID –15) \v SVz 86 Van [with overlay]
/w LWV 87 Water Station \w SWV 87 Flooding
/x LXV 88 X-APRS (Unix) \x SXV 88
/y LYV 89 Yagi at QTH \y SYV 89
/z LZV 90 \z SZV 90
/{ J1V 91 \{ Q1V 91 Fog
/| J2V 92 [Reserved — TNC Stream Switch] \| Q2V 92 [Reserved — TNC Stream Switch]
/} J3V 93 \} Q3V 93
/~ J4V 94 [Reserved — TNC Stream Switch] \~ Q4V 94 [Reserved — TNC Stream Switch]"""

base_table = {}
xyz_table = {}
cnn_table = {}
for line in raw_table.split('\n'):
    match = re.match(rex, line)
    primary_overlay = match[3] == "z"
    secondary_overlay = match[8] == "z"
    base_table[match[1]] = {"primary_icon": match[5], "primary_overlay": primary_overlay, "secondary_icon": match[10], "secondary_overlay": secondary_overlay}
    xyz_table[match[2]] = {"icon": match[5], "overlay": primary_overlay}
    xyz_table[match[7]] = {"icon": match[10], "overlay": secondary_overlay}
    cnn_table[match[4]] = {"primary_icon": match[5], "primary_overlay": primary_overlay, "secondary_icon": match[10], "secondary_overlay": secondary_overlay}

with open('tables', 'w') as table_file:
    table_file.write('----------------BASE TABLE--------------\n')
    table_file.write(str(base_table))
    table_file.write("\n")
    table_file.write('----------------XYZ TABLE--------------\n')
    table_file.write(str(xyz_table))
    table_file.write("\n")
    table_file.write('----------------CNN TABLE--------------\n')
    table_file.write(str(cnn_table))
    table_file.write("\n")

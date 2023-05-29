from shared.aprs import APRSDecoder
from shared.ax25 import AX25Frame


frame = AX25Frame.parse_raw('{"modulo": 1, "address_field": {"source": {"callsign": "K5RHD", "ssid": "10", "reserved_bit_5": true, "reserved_bit_6": true, "command_repeat_bit": false}, "destination": {"callsign": "APMI06", "ssid": "0", "reserved_bit_5": true, "reserved_bit_6": true, "command_repeat_bit": false}, "path": [{"callsign": "N0AUX", "ssid": "1", "reserved_bit_5": true, "reserved_bit_6": true, "command_repeat_bit": true}, {"callsign": "WIDE1", "ssid": "0", "reserved_bit_5": true, "reserved_bit_6": true, "command_repeat_bit": true}], "length": 28}, "control_field": {"frame_type": 8196, "length": 1, "poll_final": false, "sequence": null, "receive": null}, "pid": 240, "information": "@172045#3950.70N/10505.14W&PHG8230 Randy K5RHD.73@GMAIL.COM Arvada-CO "}')
print(APRSDecoder.from_ax25(frame))

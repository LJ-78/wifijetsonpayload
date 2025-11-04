# # # kismet_utils.py
import requests
import re
from typing import List, Dict

KISMET_URL = "http://localhost:2501"

# Crypt bitfield constants for fallback decoding
CRYPT_NONE = 0
CRYPT_UNKNOWN = (1 << 0)
CRYPT_WEP = (1 << 1)
CRYPT_LAYER3 = (1 << 2)
CRYPT_WEP40 = (1 << 3)
CRYPT_WEP104 = (1 << 4)
CRYPT_TKIP = (1 << 5)
CRYPT_WPA = (1 << 6)
CRYPT_PSK = (1 << 7)
CRYPT_AES_OCB = (1 << 8)
CRYPT_AES_CCM = (1 << 9)
CRYPT_WPA_MIGMODE = (1 << 10)
CRYPT_EAP = (1 << 11)
CRYPT_PEAP = (1 << 12)
CRYPT_LEAP = (1 << 13)
CRYPT_TTLS = (1 << 14)
CRYPT_TLS = (1 << 15)
CRYPT_ISAKMP = (1 << 16)
CRYPT_PPTP = (1 << 17)
CRYPT_WPA2 = (1 << 18)
CRYPT_SAE = (1 << 19)
CRYPT_OWE = (1 << 20)
CRYPT_WPS = (1 << 21)
CRYPT_VERSION_WPA1 = (1 << 22)
CRYPT_VERSION_WPA2 = (1 << 23)
CRYPT_VERSION_WPA3 = (1 << 24)

def get_crypt_string(crypt_set: int) -> str:
    if crypt_set == CRYPT_NONE:
        return "Open"
    
    ret = []
    if crypt_set & CRYPT_VERSION_WPA3 or crypt_set & CRYPT_SAE:
        ret.append("WPA3")
    if crypt_set & CRYPT_VERSION_WPA2 or crypt_set & CRYPT_WPA2:
        ret.append("WPA2")
    if crypt_set & CRYPT_VERSION_WPA1 or crypt_set & CRYPT_WPA:
        ret.append("WPA")
    if crypt_set & CRYPT_WPA_MIGMODE:
        ret.append("WPA-MIGMODE")
    if crypt_set & CRYPT_OWE:
        ret.append("OWE")
    if crypt_set & CRYPT_PSK:
        ret.append("PSK")
    if crypt_set & CRYPT_AES_CCM:
        ret.append("AES(CCM)")
    if crypt_set & CRYPT_AES_OCB:
        ret.append("AES(OCB)")
    if crypt_set & CRYPT_TKIP:
        ret.append("TKIP")
    if crypt_set & CRYPT_WEP104:
        ret.append("WEP104")
    if crypt_set & CRYPT_WEP40:
        ret.append("WEP40")
    if crypt_set & CRYPT_WEP:
        ret.append("WEP")
    if crypt_set & CRYPT_LAYER3:
        ret.append("LAYER3")
    if crypt_set & CRYPT_EAP:
        ret.append("EAP")
    if crypt_set & CRYPT_PEAP:
        ret.append("PEAP")
    if crypt_set & CRYPT_LEAP:
        ret.append("LEAP")
    if crypt_set & CRYPT_TTLS:
        ret.append("TTLS")
    if crypt_set & CRYPT_TLS:
        ret.append("TLS")
    if crypt_set & CRYPT_ISAKMP:
        ret.append("ISAKMP")
    if crypt_set & CRYPT_PPTP:
        ret.append("PPTP")
    if crypt_set & CRYPT_WPS:
        ret.append("WPS")
    if crypt_set & CRYPT_UNKNOWN:
        ret.append("UNKNOWN")

    if not ret:
        ret.append("NONE")

    return " ".join(ret)

def get_kismet_session(username: str, password: str) -> requests.Session:
    session = requests.Session()
    auth = requests.auth.HTTPBasicAuth(username, password)
    response = session.get(f"{KISMET_URL}/session/check_session", auth=auth)
    if response.status_code != 200:
        raise ValueError("Failed to authenticate with Kismet")
    return session

def survey_wifi(kismet_session: requests.Session) -> List[Dict]:
    endpoint = f"{KISMET_URL}/devices/views/phydot11_accesspoints/devices.json"
    payload = {
        "fields": [
            "kismet.device.base.key",
            "kismet.device.base.macaddr",
            "kismet.device.base.name",
            "kismet.device.base.type",
            "dot11.device/dot11.device.advertised_ssid_map",
            "kismet.device.base.signal/kismet.common.signal.last_signal",
            "kismet.device.base.basic_crypt_set",
            "dot11.device/dot11.device.last_beaconed_ssid"
        ]
    }
    response = kismet_session.post(endpoint, json=payload)
    if response.status_code != 200:
        raise ValueError(f"Failed to fetch data from Kismet: {response.status_code} - {response.text}")
    devices = response.json()
    
    networks = []
    mac_re = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
    
    for device in devices:
        # print("Dev: ", device)

        # Parse fields from device record
        mac = device.get("kismet.device.base.macaddr", "Unknown")
        base_name = device.get("kismet.device.base.name", "Unknown")
        signal = device.get("kismet.common.signal.last_signal", None)
        
        # Get advertised_ssid_map - it's a LIST of dicts
        ssid_map = device.get("dot11.device.advertised_ssid_map", [])
        
        ssid = base_name
        channel = "Unknown"
        security = "Unknown"
        
        if ssid_map and isinstance(ssid_map, list) and len(ssid_map) > 0:
            # Get first entry from the list
            first_ssid_info = ssid_map[0]
            ssid = first_ssid_info.get("dot11.advertisedssid.ssid", base_name)
            channel = first_ssid_info.get("dot11.advertisedssid.channel", "Unknown")
            security = first_ssid_info.get("dot11.advertisedssid.crypt_string", "Unknown")
            
            # Fallback if no crypt_string
            if not security or security == "Unknown":
                crypt_set = first_ssid_info.get("dot11.advertisedssid.crypt_set", 0)
                security = get_crypt_string(crypt_set)
        
        # Handle hidden SSIDs
        if mac_re.match(ssid) or ssid == '':
            ssid = "Hidden"
        
        networks.append({
            "ssid": ssid,
            "security": security,
            "signal": signal,
            "mac": mac,
            "channel": channel
        })
    
    return networks



# # # # kismet_utils.py
# import requests
# import re
# from typing import List, Dict

# KISMET_URL = "http://localhost:2501"

# # Crypt bitfield constants for fallback decoding
# CRYPT_NONE = 0
# CRYPT_UNKNOWN = (1 << 0)
# CRYPT_WEP = (1 << 1)
# CRYPT_LAYER3 = (1 << 2)
# CRYPT_WEP40 = (1 << 3)
# CRYPT_WEP104 = (1 << 4)
# CRYPT_TKIP = (1 << 5)
# CRYPT_WPA = (1 << 6)
# CRYPT_PSK = (1 << 7)
# CRYPT_AES_OCB = (1 << 8)
# CRYPT_AES_CCM = (1 << 9)
# CRYPT_WPA_MIGMODE = (1 << 10)
# CRYPT_EAP = (1 << 11)
# CRYPT_PEAP = (1 << 12)
# CRYPT_LEAP = (1 << 13)
# CRYPT_TTLS = (1 << 14)
# CRYPT_TLS = (1 << 15)
# CRYPT_ISAKMP = (1 << 16)
# CRYPT_PPTP = (1 << 17)
# CRYPT_WPA2 = (1 << 18)
# CRYPT_SAE = (1 << 19)
# CRYPT_OWE = (1 << 20)
# CRYPT_WPS = (1 << 21)
# CRYPT_VERSION_WPA1 = (1 << 22)
# CRYPT_VERSION_WPA2 = (1 << 23)
# CRYPT_VERSION_WPA3 = (1 << 24)

# def get_crypt_string(crypt_set: int) -> str:
#     if crypt_set == CRYPT_NONE:
#         return "Open"
    
#     ret = []
#     if crypt_set & CRYPT_VERSION_WPA3 or crypt_set & CRYPT_SAE:
#         ret.append("WPA3")
#     if crypt_set & CRYPT_VERSION_WPA2 or crypt_set & CRYPT_WPA2:
#         ret.append("WPA2")
#     if crypt_set & CRYPT_VERSION_WPA1 or crypt_set & CRYPT_WPA:
#         ret.append("WPA")
#     if crypt_set & CRYPT_WPA_MIGMODE:
#         ret.append("WPA-MIGMODE")
#     if crypt_set & CRYPT_OWE:
#         ret.append("OWE")
#     if crypt_set & CRYPT_PSK:
#         ret.append("PSK")
#     if crypt_set & CRYPT_AES_CCM:
#         ret.append("AES(CCM)")
#     if crypt_set & CRYPT_AES_OCB:
#         ret.append("AES(OCB)")
#     if crypt_set & CRYPT_TKIP:
#         ret.append("TKIP")
#     if crypt_set & CRYPT_WEP104:
#         ret.append("WEP104")
#     if crypt_set & CRYPT_WEP40:
#         ret.append("WEP40")
#     if crypt_set & CRYPT_WEP:
#         ret.append("WEP")
#     if crypt_set & CRYPT_LAYER3:
#         ret.append("LAYER3")
#     if crypt_set & CRYPT_EAP:
#         ret.append("EAP")
#     if crypt_set & CRYPT_PEAP:
#         ret.append("PEAP")
#     if crypt_set & CRYPT_LEAP:
#         ret.append("LEAP")
#     if crypt_set & CRYPT_TTLS:
#         ret.append("TTLS")
#     if crypt_set & CRYPT_TLS:
#         ret.append("TLS")
#     if crypt_set & CRYPT_ISAKMP:
#         ret.append("ISAKMP")
#     if crypt_set & CRYPT_PPTP:
#         ret.append("PPTP")
#     if crypt_set & CRYPT_WPS:
#         ret.append("WPS")
#     if crypt_set & CRYPT_UNKNOWN:
#         ret.append("UNKNOWN")

#     if not ret:
#         ret.append("NONE")

#     return " ".join(ret)

# def get_kismet_session(username: str, password: str) -> requests.Session:
#     session = requests.Session()
#     auth = requests.auth.HTTPBasicAuth(username, password)
#     response = session.get(f"{KISMET_URL}/session/check_session", auth=auth)
#     if response.status_code != 200:
#         raise ValueError("Failed to authenticate with Kismet")
#     return session

# def survey_wifi(kismet_session: requests.Session) -> List[Dict]:
#     endpoint = f"{KISMET_URL}/devices/views/phydot11_accesspoints/devices.json"
#     payload = {
#         "fields": [
#             "kismet.device.base.key",
#             "kismet.device.base.macaddr",
#             "kismet.device.base.name",
#             "kismet.device.base.type",
#             "dot11.device/dot11.device.advertised_ssid_map",
#             "kismet.device.base.signal/kismet.common.signal.last_signal",
#             "kismet.device.base.basic_crypt_set",
#             "dot11.device/dot11.device.last_beaconed_ssid",
#             "dot11.device/dot11.advertisedssid.crypt_string"
#         ]
#     }
#     response = kismet_session.post(endpoint, json=payload)
#     if response.status_code != 200:
#         raise ValueError(f"Failed to fetch data from Kismet: {response.status_code} - {response.text}")
#     devices = response.json()
#     # print(devices)  # For debugging raw response - remove after confirmation
    
#     networks = []
#     mac_re = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
#     for device in devices:
#         print("Dev: ", device)


#         ssid_map_key = "dot11.device/dot11.device.advertised_ssid_map"
#         signal_key = "kismet.device.base.signal/kismet.common.signal.last_signal"
#         mac = device.get("kismet.device.base.macaddr", "Unknown")
#         signal = device.get(signal_key, None)
#         base_name = device.get("kismet.device.base.name", "Unknown")
#         last_beaconed_ssid = device.get("dot11.device/dot11.device.last_beaconed_ssid", "")
#         security_info_key = device.get("dot11.advertisedssid.crypt_string", "Nothing")
#         security = "Unknown"
        
#         print(device['dot11.advertisedssid.crypt_string'])
        
#         ssid = base_name
#         if ssid_map_key in device and device[ssid_map_key]:
#             ssid_map = device[ssid_map_key]
#             if ssid_map:
#                 first_key = list(ssid_map.keys())[0]
#                 ssid_info = ssid_map[first_key]["dot11.advertisedssid"]
#                 ssid = ssid_info.get("ssid", base_name)
                
#                 security = ssid_info.get("crypt_string", "Unknown")
#                 if security == "Unknown" or not security:
#                     crypt_set = ssid_info.get("crypt_set", 0)
#                     print(f"SSID {ssid} crypt_set: {crypt_set}")  # Debug
#                     security = get_crypt_string(crypt_set)
#         else:
#             ssid = last_beaconed_ssid if last_beaconed_ssid else base_name
#             if ssid == "" or ssid.lower() == "<hidden ssid>":
#                 ssid = "Hidden"
#             crypt_set = device.get("kismet.device.base.basic_crypt_set", 0)
#             print(f"SSID {ssid} basic_crypt_set: {crypt_set}")  # Debug
#             security = get_crypt_string(crypt_set)
        
#         if mac_re.match(ssid) or ssid == '':
#             ssid = "Hidden"
        
#         networks.append({
#             "ssid": ssid,
#             "security": security,
#             "signal": signal,
#             "mac": mac
#         })
#     return networks

def get_memory_manufacturer(manufacturer_code: str):
    """
    Get the manufacturer of the memory module
    :param manufacturer_code:
    :return:
    """
    MEMORY_MANUFACTURERS = {
        "0x2C00": "Micron",
        "0x5105": "Qimonda",
        "0x802C": "Micron",
        "0x80AD": "Hynix",
        "0x80CE": "Samsung",
        "0x8551": "Qimonda",
        "0xAD00": "Hynix",
        "0xCE00": "Samsung"
    }
    return MEMORY_MANUFACTURERS.get(manufacturer_code, "Unknown")


def get_manufacturer(name: str) -> str:
    """
    Get the manufacturer of the device
    :param name:
    :return:
    """
    if not name:
        return "Unknown"
    MANUFACTURERS = ["Cisco", "Intel", "Emulex", "Samsung", "Hynix", "Micron", "Qimonda", "LSI Logic", "Cypress",
                     "Broadcom", 'Toshiba']
    for manufacturer in MANUFACTURERS:
        if manufacturer.lower() in name.lower():
            return manufacturer
    return "Unknown"


def combine_dict_values(original: dict, additional: dict) -> dict:
    """
    Combine two dictionaries together and append or update their nested values, if any
    :param original: The original dictionary
    :param additional: The additional dictionary
    :return:
    """
    results = original.copy()
    for key, value in additional.items():
        if key not in original.keys():
            results[key] = value
        else:
            if isinstance(original[key], list):
                results[key].extend(value)
            elif isinstance(original[key], dict):
                results[key].update(value)
            elif isinstance(original[key], str):
                results[key] = value
            elif isinstance(original[key], int):
                results[key] = value
            elif original[key] is None:
                results[key] = value
            else:
                raise TypeError(f'Unknown instance type for value {value} of key {key}. Type: {type(value)}')
    return results


def get_memory_location(model: str, memory_id: str) -> str:
    """
    Get the location of the memory module
    :param model:
    :param memory_id:
    :return:
    """
    C4_MEMORY_LOCATIONS = {
        "1": "DIMM_A1",
        "2": "DIMM_A2",
        "3": "DIMM_A3",
        "4": "DIMM_B1",
        "5": "DIMM_B2",
        "6": "DIMM_B3",
        "7": "DIMM_C1",
        "8": "DIMM_C2",
        "9": "DIMM_C3",
        "10": "DIMM_D1",
        "11": "DIMM_D2",
        "12": "DIMM_D3",
        "13": "DIMM_E1",
        "14": "DIMM_E2",
        "15": "DIMM_E3",
        "16": "DIMM_F1",
        "17": "DIMM_F2",
        "18": "DIMM_F3",
        "19": "DIMM_G1",
        "20": "DIMM_G2",
        "21": "DIMM_G3",
        "22": "DIMM_H1",
        "23": "DIMM_H2",
        "24": "DIMM_H3",
    }
    C5_MEMORY_LOCATIONS = {
        "1": "DIMM_A1",
        "2": "DIMM_A2",
        "3": "DIMM_B1",
        "4": "DIMM_B2",
        "5": "DIMM_C1",
        "6": "DIMM_C2",
        "7": "DIMM_D1",
        "8": "DIMM_D2",
        "9": "DIMM_E1",
        "10": "DIMM_E2",
        "11": "DIMM_F1",
        "12": "DIMM_F2",
        "13": "DIMM_G1",
        "14": "DIMM_G2",
        "15": "DIMM_H1",
        "16": "DIMM_H2",
        "17": "DIMM_I1",
        "18": "DIMM_I2",
        "19": "DIMM_J1",
        "20": "DIMM_J2",
        "21": "DIMM_K1",
        "22": "DIMM_K2",
        "23": "DIMM_L1",
        "24": "DIMM_L2",
        "25": "DIMM_M1",
        "26": "DIMM_M2",
    }
    if "M4" in model:
        return C4_MEMORY_LOCATIONS.get(memory_id, f"Unknown_{memory_id}")
    elif "M5" in model:
        return C5_MEMORY_LOCATIONS.get(memory_id, f"Unknown_{memory_id}")


def get_wwn_hex(wwn: str) -> str:
    """
    Convert the WWN in decimal format to hexadecimal format
    :param wwn:
    :return:
    """
    wwn_hex = format(int(wwn), 'x')
    # Initialize an empty string
    wwn_hex_colon = ""
    for i in range(0, len(wwn_hex), 2):
        # Concatenate the current slice of 2 characters and a colon
        wwn_hex_colon += wwn_hex[i:i + 2] + ":"
    # Remove the last colon
    wwn_hex_colon = wwn_hex_colon[:-1]
    return wwn_hex_colon

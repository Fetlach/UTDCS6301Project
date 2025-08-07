import os
import json
import base64
import copy

def serializeJSON(out_path, shares_encrypted: json) -> bool:
    jsonCopy = copy.deepcopy(shares_encrypted)
    if len(jsonCopy["shares"]) > 0:
        print(jsonCopy["shares"][0])
    
    # --- convert objects to json-compatible structure
    for i in range(len(jsonCopy["public_keys"])):
        jsonCopy["public_keys"][i] = base64.b64encode(jsonCopy["public_keys"][i]).decode('utf-8')
    
    for i in range(len(jsonCopy["shares"])):
        jsonCopy["shares"][i] = base64.b64encode(jsonCopy["shares"][i]).decode('utf-8')

    with open(out_path, 'w', encoding='utf-8') as f_out:
        json.dump(jsonCopy, f_out, indent=4)

    
    return True

def deserializeJSON(in_path) -> json:
    jsonCopy = {
        "public_keys": [],
        "shares": [],
        "share_positions": [],
        "numShares": 0,
        "threshold": 0
    }
    with open(in_path, 'r') as f_in:
        jsonCopy = json.load(f_in)

    for i in range(len(jsonCopy["public_keys"])):
        jsonCopy["public_keys"][i] = base64.b64decode(jsonCopy["public_keys"][i].encode('utf-8'))
    
    for i in range(len(jsonCopy["shares"])):
        jsonCopy["shares"][i] = base64.b64decode(jsonCopy["shares"][i].encode('utf-8'))

    if len(jsonCopy["shares"]) > 0:
        print(jsonCopy["shares"][0])
    return jsonCopy
    
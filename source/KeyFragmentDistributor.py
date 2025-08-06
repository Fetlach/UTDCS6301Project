import os
import json
import base64

def serializeJSON(out_path, shares_encrypted: json) -> bool:
    jsonCopy = shares_encrypted
    
    # --- convert objects to json-compatible structure
    for i in range(len(jsonCopy["public_keys"])):
        jsonCopy["public_keys"][i] = base64.b64encode(jsonCopy["public_keys"][i]).decode('utf-8')
    for i in range(len(jsonCopy["private_keys"])):
        jsonCopy["private_keys"][i] = base64.b64encode(jsonCopy["private_keys"][i]).decode('utf-8')
    for i in range(len(jsonCopy["shares"])):
        jsonCopy["shares"][i] = base64.b64encode(jsonCopy["shares"][i]).decode('utf-8')

    with open(os.path.join(out_path, "log_encryption.txt"), 'w', encoding='utf-8') as f_out:
        json.dump(jsonCopy, f_out, indent=4)
    return True

def deserializeJSON(in_path) -> json:
    jsonCopy = {}
    with open(os.path.join(in_path, "log_encryption.txt"), 'r') as f_in:
        jsonCopy = json.load(f_in)

    for i in range(len(jsonCopy["public_keys"])):
        jsonCopy["public_keys"][i] = base64.b64decode(jsonCopy["public_keys"][i].encode('utf-8'))
    for i in range(len(jsonCopy["private_keys"])):
        jsonCopy["private_keys"][i] = base64.b64decode(jsonCopy["private_keys"][i].encode('utf-8'))
    for i in range(len(jsonCopy["shares"])):
        jsonCopy["shares"][i] = base64.b64decode(jsonCopy["shares"][i].encode('utf-8'))

    return jsonCopy
    
def output(shares_encrypted) -> bool:
    with open(out_path, 'wb') as f_out:
        for share in shares_encrypted:
            f_out.write()
    return True
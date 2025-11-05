from sd_jwt.common import SDObj

def build_claims(paths: dict):
    user_claims = {}
    for path_name, path_value in paths.items():
        if path_name == "_sd":
            continue
        elif "value" not in path_value and "display" not in path_value:
            sd = path_value["_sd"]
            if sd:
                user_claims[SDObj(path_name)] = build_claims(path_value)
            else:
                user_claims[path_name] = build_claims(path_value)
        else:
            sd = path_value["_sd"]
            val = path_value["value"]
            if sd:
                if isinstance(val, list):
                    list_claims = []
                    for item in val:
                        print(f'list item: {item}')
                        # TODO: handle if item is an object
                        list_claims.append(SDObj(item))
                    user_claims[SDObj(path_name)] = list_claims
                else:
                    user_claims[SDObj(path_name)] = val
            else:
                user_claims[path_name] = val
    return user_claims

def build_claims_for_display(out: list, paths: dict, curr_path: list):
    for path_name, path_value in paths.items():
        if path_name == "_sd":
            continue
        new_path = curr_path.copy()
        new_path.append(path_name)
        if "value" not in path_value:
            build_claims_for_display(out, path_value, new_path)
        else:
            claim = {}
            claim["path"] = new_path
            if "display" in path_value:
                display = {"locale": "en-US"}
                display["name"] = path_value["display"]
                display = [display]
                claim["display"] = display
            out.append(claim)
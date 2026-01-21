import os
import json
import urllib.parse


# -----------------------------
#  SNI extraction
# -----------------------------
def extract_sni(stream, security):
    # TLS
    if security == "tls":
        sni = stream.get("tls", {}).get("server_name")
        if sni:
            return sni
        sni = stream.get("tlsSettings", {}).get("serverName")
        if sni:
            return sni

    # Reality
    if security == "reality":
        sni = stream.get("tls", {}).get("server_name")
        if sni:
            return sni
        sni = stream.get("reality", {}).get("server_name")
        if sni:
            return sni
        sni = stream.get("realitySettings", {}).get("serverName")
        if sni:
            return sni

    # WS fallback
    host = stream.get("wsSettings", {}).get("headers", {}).get("Host")
    if host:
        return host

    return None


# -----------------------------
#  Reality detection
# -----------------------------
def is_reality_enabled(stream, security):
    if security == "reality":
        return True

    if stream.get("reality", {}).get("enabled") is True:
        return True

    if stream.get("realitySettings", {}).get("enabled") is True:
        return True

    return False


# -----------------------------
#  Reality parameters
# -----------------------------
def extract_reality_params(stream):
    params = {}

    # sing-box style
    rs = stream.get("realitySettings", {})
    if rs:
        if rs.get("publicKey"):
            params["pbk"] = rs.get("publicKey")
        if rs.get("shortId"):
            params["sid"] = rs.get("shortId")
        if rs.get("fingerprint"):
            params["fp"] = rs.get("fingerprint")
        if rs.get("spiderX"):
            params["spx"] = rs.get("spiderX")

    # v2ray-core style
    r = stream.get("reality", {})
    if r:
        if r.get("public_key"):
            params["pbk"] = r.get("public_key")
        if r.get("short_id"):
            params["sid"] = r.get("short_id")
        if r.get("fingerprint"):
            params["fp"] = r.get("fingerprint")

    return params


# -----------------------------
#  uTLS parameters
# -----------------------------
def extract_utls_params(stream):
    utls = stream.get("utls", {})
    if not utls.get("enabled"):
        return {}

    fp = utls.get("fingerprint")
    if fp:
        return {"fp": fp}

    return {}


# -----------------------------
#  Build VLESS URL
# -----------------------------
def extract_vless_from_outbound(ob):
    # v2ray-core format
    if ob.get("protocol") == "vless":
        return extract_vless_v2ray(ob)

    # sing-box format
    if ob.get("type") == "vless":
        return extract_vless_singbox(ob)

    return None


# -----------------------------
#  v2ray-core / v2rayN format
# -----------------------------
def extract_vless_v2ray(ob):
    settings = ob.get("settings", {})
    vnext = settings.get("vnext", [])
    if not vnext:
        return None

    node = vnext[0]
    address = node.get("address")
    port = node.get("port")
    user = node.get("users", [{}])[0]

    uuid = user.get("id")
    flow = user.get("flow")
    encryption = user.get("encryption", "none")

    stream = ob.get("streamSettings", {})
    network = stream.get("network", "tcp")
    security = stream.get("security", "none")

    params = {"encryption": encryption, "type": network}

    if flow:
        params["flow"] = flow

    # Reality
    if is_reality_enabled(stream, security):
        params["security"] = "reality"
        params.update(extract_reality_params(stream))
    else:
        if security != "none":
            params["security"] = security

    # SNI
    sni = extract_sni(stream, params.get("security"))
    if sni:
        params["sni"] = sni

    # uTLS (only if no Reality fingerprint)
    utls = extract_utls_params(stream)
    for k, v in utls.items():
        if k not in params:
            params[k] = v

    query = urllib.parse.urlencode(params)
    return f"vless://{uuid}@{address}:{port}?{query}#imported"


# -----------------------------
#  sing-box format
# -----------------------------
def extract_vless_singbox(ob):
    address = ob.get("server")
    port = ob.get("server_port")
    uuid = ob.get("uuid")
    flow = ob.get("flow")
    encryption = ob.get("encryption", "none")

    tls = ob.get("tls", {})
    network = "tcp"

    params = {"encryption": encryption, "type": network}

    if flow:
        params["flow"] = flow

    # Reality
    if tls.get("reality", {}).get("enabled") is True:
        params["security"] = "reality"
        params.update({
            "pbk": tls["reality"].get("public_key"),
            "sid": tls["reality"].get("short_id")
        })
    else:
        if tls.get("enabled"):
            params["security"] = "tls"

    # SNI
    if tls.get("server_name"):
        params["sni"] = tls.get("server_name")

    # uTLS
    utls = tls.get("utls", {})
    if utls.get("enabled") and utls.get("fingerprint"):
        if "fp" not in params:
            params["fp"] = utls.get("fingerprint")

    query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
    return f"vless://{uuid}@{address}:{port}?{query}#imported"


# -----------------------------
#  Process JSON file
# -----------------------------
def process_json_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except:
        return []

    outbounds = []

    if isinstance(data, dict):
        if "outbounds" in data:
            outbounds = data["outbounds"]
        elif "outbound" in data:
            outbounds = [data["outbound"]]
        else:
            outbounds = [data]

    links = []
    for ob in outbounds:
        link = extract_vless_from_outbound(ob)
        if link:
            links.append(link)

    return links


# -----------------------------
#  Main
# -----------------------------
def main():
    for filename in os.listdir("."):
        if filename.endswith(".json"):
            links = process_json_file(filename)
            if links:
                print(f"\n=== {filename} ===")
                for link in links:
                    print(link)


if __name__ == "__main__":
    main()
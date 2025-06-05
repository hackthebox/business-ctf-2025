import snap7

from snap7.util import set_string



def print_menu():

    print("\n=== S7 HVAC Client ===")

    print("1. Read from Data Block")

    print("2. Write to Data Block")

    print("3. Exit")

    print("====================")



def read_db(client):

    db_num = int(input("Enter DB number (1-5): "))

    offset = int(input("Enter start offset (0-49): "))

    size = int(input("Enter size to read (1-50): "))

    

    try:

        data = client.db_read(db_num, offset, size)

        text = data.decode('utf-8', errors='ignore').rstrip('\x00')

        print(f"DB{db_num} [offset {offset}, size {size}]: {text}")

    except Exception as e:

        print(f"Error reading DB{db_num}: {e}")



def write_db(client):

    db_num = int(input("Enter DB number (1-5): "))

    offset = int(input("Enter start offset (0-49): "))

    value = input("Enter value to write: ")

    

    # Convert input to bytes, pad/truncate to fit DB structure

    value_bytes = value.encode('utf-8')

    max_size = 50 - offset  # Remaining space in DB from offset

    if len(value_bytes) > max_size:

        print(f"Warning: Value truncated to fit {max_size} bytes")

        value_bytes = value_bytes[:max_size]

    

    try:

        client.db_write(db_num, offset, value_bytes)

        print(f"Wrote '{value}' to DB{db_num} at offset {offset}")

    except Exception as e:

        print(f"Error writing to DB{db_num}: {e}")



def main():

    # Connect to server

    client = snap7.client.Client()

    try:

        client.connect("10.0.2.5", 0, 1, 1338)  # IP, Rack 0, Slot 1, Port 1338

        if not client.get_connected():

            print("Connection failed")

            return

        print("Connected to S7 HVAC Server on 0.0.0.0:1338")

    except Exception as e:

        print(f"Connection error: {e}")

        return



    # Main loop

    while True:

        print_menu()

        choice = input("Select option (1-3): ")

        

        if choice == "1":

            read_db(client)

        elif choice == "2":

            write_db(client)

        elif choice == "3":

            break

        else:

            print("Invalid option, try again")



    # Cleanup

    client.disconnect()

    client.destroy()

    print("Client stopped")



if __name__ == "__main__":

    main()
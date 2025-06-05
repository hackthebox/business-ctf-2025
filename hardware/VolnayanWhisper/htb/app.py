import sys
import time

__version__ = "2.0"

class ModemPico:
    def __init__(self):
        # Initialize variables
        self.__echo = False
        self.__pin = True
        self.__cfun = 1
        
        # SMS related variables
        self.__sms_storage = []  # Just store received PDUs as-is
        self.__pdu_mode = False  # Start in text mode
        self.__sms_message_format = 0  # 0=PDU mode, 1=text mode
        self.__new_message_indications = True
        self.__service_center_address = "+12345678901"  # Default SCA

    def send(self, data):
        """Send data to stdout"""
        if isinstance(data, str):
            sys.stdout.write(data)
        else:
            sys.stdout.buffer.write(data)

    def execute_cmd(self, buf):
        delay = 0

        # Remove tail if exists
        if buf[-1] == "\n":
            buf = buf[:-1]

        # Prepare for multicmds
        if "\n" in buf:
            cmds = buf.split("\n")
        else:
            cmds = [buf]

        # For each cmd
        for cmd in cmds:
            # Clean cmd
            if cmd.endswith("\r"):
                cmd = cmd[:-1]

            if cmd == "+++":
                answer = None

            elif cmd == "":
                answer = None

            elif cmd == "AT":
                answer = "\r\nOK"

            elif cmd == "ATZ":
                answer = "\r\nOK"
                # Reset values
                self.__echo = False
                self.__pin = True
                self.__cfun = 1
                self.__pdu_mode = False
                self.__sms_message_format = 0
                self.__new_message_indications = True

            elif cmd == "ATI":
                answer = f"\r\nPhantomNet Modem v{__version__}"

            elif cmd == "ATE0":
                answer = "\r\nOK"
                self.__echo = False

            elif cmd == "ATE1":
                answer = "\r\nOK"
                self.__echo = True

            elif cmd == "AT+CFUN=1":
                answer = "\r\nOK"
                if self.__cfun != 1:
                    self.__cfun = 1
                    delay = 1

            elif cmd == "AT+CFUN=6":
                answer = "\r\nOK"
                if self.__cfun != 6:
                    self.__cfun = 6
                    delay = 1

            elif cmd == "AT+CPIN?":
                if self.__pin:
                    answer = "\r\n+CPIN: READY\r\n\r\nOK"
                else:
                    answer = "\r\n+CPIN: SIM PIN\r\n\r\nOK"

            elif cmd.startswith("AT+CPIN="):
                pin = cmd[8:]
                self.__pin = True
                answer = "\r\n+CPIN: READY\r\n\r\nSMS DONE\r\n\r\nPB DONE\r\n\r\nOK"
                
            # SMS PDU mode commands
            elif cmd == "AT+CMGF?":
                answer = f"\r\n+CMGF: {self.__sms_message_format}\r\n\r\nOK"
                
            elif cmd.startswith("AT+CMGF="):
                mode = int(cmd[8:])
                self.__sms_message_format = mode
                self.__pdu_mode = (mode == 0)
                answer = "\r\nOK"
                
            elif cmd == "AT+CMGL=4" and self.__pdu_mode:
                # List all SMS in PDU mode (simplified)
                if not self.__sms_storage:
                    answer = "\r\nOK"
                else:
                    response_parts = []
                    for i, sms in enumerate(self.__sms_storage):
                        response_parts.append(f"\r\n+CMGL: {i},{sms['status']},,{len(sms['pdu']) // 2}")
                        response_parts.append(f"\r\n{sms['pdu']}")
                    response_parts.append("\r\n\r\nOK")
                    answer = "".join(response_parts)
                
            elif cmd.startswith("AT+CMGR=") and self.__pdu_mode:
                # Read SMS in PDU mode (simplified)
                try:
                    index = int(cmd[8:])
                    if 0 <= index < len(self.__sms_storage):
                        sms = self.__sms_storage[index]
                        answer = f"\r\n+CMGR: {sms['status']},,,{len(sms['pdu']) // 2}\r\n{sms['pdu']}\r\n\r\nOK"
                    else:
                        answer = "\r\nERROR"
                except:
                    answer = "\r\nERROR"
                    
            elif cmd.startswith("AT+CMGS=") and self.__pdu_mode:
                # Send SMS in PDU mode (simplified - just store the raw PDU)
                answer = "\r\n> "
                self.send(answer.encode())
                
                # Get PDU data
                pdu_data = ""
                while True:
                    char = sys.stdin.read(1)
                    if char == chr(26):  # CTRL+Z
                        break
                    pdu_data += char
                
                # No decoding, just store and respond
                self.__sms_storage.append({
                    'pdu': pdu_data.strip(),
                    'status': 1
                })
                answer = f"\r\n+CMGS: {len(self.__sms_storage) - 1}\r\n\r\nOK"
                    
            elif cmd == "AT+CNMI?":
                answer = "\r\n+CNMI: 1,1,0,0,0\r\n\r\nOK"
                
            elif cmd.startswith("AT+CNMI="):
                # New message indications
                parts = cmd[8:].split(",")
                # Simple implementation - just enable/disable message indications
                if len(parts) >= 2 and parts[1] == "1":
                    self.__new_message_indications = True
                else:
                    self.__new_message_indications = False
                answer = "\r\nOK"
                
            elif cmd == "AT+CSCA?":
                # Get SMS service center address
                answer = f'\r\n+CSCA: "{self.__service_center_address}",145\r\n\r\nOK'
                
            elif cmd.startswith("AT+CSCA="):
                # Set SMS service center address
                parts = cmd[8:].split(",")
                if len(parts) >= 1:
                    self.__service_center_address = parts[0].strip('"')
                answer = "\r\nOK"
                
            elif cmd == "AT+CSMS?":
                # SMS service
                answer = "\r\n+CSMS: 0,1,1,1\r\n\r\nOK"
                
            elif cmd.startswith("AT+CSMS="):
                # Set SMS service
                answer = "\r\n+CSMS: 1,1,1\r\n\r\nOK"
                
            else:
                answer = "\r\nERROR"

            # Send echo
            if self.__echo:
                echo_cmd = cmd + "\r\n"
                self.send(echo_cmd.encode())

            # Send answer
            if answer:
                self.send(answer.encode())

            # Do delay
            if delay:
                time.sleep(delay)


    def run(self):
        """Main loop to read from sys.stdin"""
    
        buffer = ""
        
        # Main loop
        while True:
            try:
                # Read from stdin
                char = sys.stdin.read(1)
                
                # Add to buffer
                if char:
                    buffer += char
                    
                    # Check for command termination
                    if buffer.endswith("\r") or buffer.endswith("\n"):
                        if buffer.strip():
                            self.execute_cmd(buffer)
                        buffer = ""
                else:
                    # No more data, wait a bit
                    time.sleep(0.1)
                    
            except KeyboardInterrupt:              
                break
            except Exception as e:
                time.sleep(0.1)

# Start the modem simulator
if __name__ == "__main__":
    try:
        modem = ModemPico()
        modem.run()
    except KeyboardInterrupt:
        print("\nModem simulator stopped by user")
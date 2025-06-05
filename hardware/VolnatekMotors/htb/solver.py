#!/usr/bin/python3

from socket import *
import logging
from sys import argv

HOST, PORT = argv[1], int(argv[2])
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('UDS-Client')


sock = socket(AF_INET, SOCK_STREAM)
sock.connect((HOST, PORT))
logger.info(f"Connected to {HOST}:{PORT}")

def TesterPresent(sock):
    logger.info("Sending a hearbeat: TesterPresent service")

    payload = bytearray([0x1, 0x3E])
    logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
    sock.send(payload)

    response = bytearray(sock.recv(8))
    status = "positive" if response[1] == 0x7E else "negative"
    logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))} ({status})")

def ChangeSession(sock, ses_id):
    logger.info("Sending a change session request: DiagnosticSessionControl service")

    payload = bytearray([0x2, 0x10, ses_id])
    logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
    sock.send(payload)

    response = bytearray(sock.recv(8))
    status = "positive" if response[1] == 0x50 else "negative"
    logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))} ({status})")


def SecurityAccessGetSeed(sock):
    payload = bytearray([0x2, 0x27, 0x1])
    logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
    sock.send(payload)

    response = bytearray(sock.recv(8))
    # status = "positive" if response[1] == 0x50 else "negative"
    seed = response[3:]

    logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))} ")
    logger.info(f"Seed: {seed}")
    
    return seed

def SecurityAccessSendPass(sock, passwd):
    payload = bytearray([0x6, 0x27, 0x2] + list(passwd))
    logger.info(f"Sending payload: {' '.join(map(lambda x: f'{x:02x}', payload))}")
    sock.send(payload)

    response = bytearray(sock.recv(8))

    logger.info(f"Response: {' '.join(map(lambda x: f'{x:02x}', response))} ")    
    return response[1] == 0x67

def ReadDataByIdentifier(sock, data_id):
    """
    Read Data By Identifier (UDS Service 0x22)
    
    Args:
        sock: Socket connection
        data_id: 2-byte data identifier (e.g., 0xF190 for VIN)
    
    Returns:
        Data value (if successful) or None (if failed)
    """
    logger.info(f"Reading data identifier: 0x{data_id:04X}")

    # Build payload: [Length, SID (0x22), Data ID MSB, Data ID LSB]
    # Length is entire payload length including the length byte
    payload = bytearray([0x3, 0x22, (data_id >> 8) & 0xFF, data_id & 0xFF])
    
    logger.info(f"Sending payload: {' '.join(f'{x:02X}' for x in payload)}")
    sock.send(payload)

    # Receive response (adjust buffer size as needed)
    response = bytearray(sock.recv(1024))
    
    if len(response) == 0:
        logger.error("No response received")
        return None
    
    # Check for positive response (0x62)
    if response[1] == 0x62:
        logger.info(f"Positive response: {' '.join(f'{x:02X}' for x in response)}")
        
        # Extract data value (skip service ID and data identifier)
        data_value = response[4:]
        logger.info(f"Data value: {' '.join(f'{x:02X}' for x in data_value)} (ASCII: {bytes(data_value).decode('ascii', errors='replace')})")
        return data_value
    else:
        logger.error(f"Negative response: {' '.join(f'{x:02X}' for x in response)}")
        return None

def ReadMemoryByAddress(sock, address, size):
    logger.info(f"Reading memory at address: 0x{address:X}, size: {size} bytes")
    
    # Format the addressing information
    # We'll use 2 bytes for address (addressSizeFormat=0x2) and 2 bytes for size (sizeFormat=0x2)
    addr_format = 0x22  # First digit: address size (2 bytes), Second digit: size bytes (2 bytes)
    
    # Build payload: [Total Length, SID (0x23), Format, Address MSB, Address LSB, Size MSB, Size LSB]
    payload = bytearray([
        0x6,                         # Length (total bytes including this byte)
        0x23,                         # Service ID (ReadMemoryByAddress)
        addr_format,                  # Address/Size format
        (address >> 8) & 0xFF,        # Address MSB
        address & 0xFF,               # Address LSB
        (size >> 8) & 0xFF,           # Size MSB
        size & 0xFF                   # Size LSB
    ])
    
    logger.info(f"Sending payload: {' '.join(f'{x:02X}' for x in payload)}")
    sock.send(payload)
    
    # Read the first 8 bytes of the response
    response = sock.recv(8)
    if not response or len(response) < 1:
        logger.error("No response received")
        return None
    
    logger.info(f"Initial response: {' '.join(f'{x:02X}' for x in response)}")
    
    # Check if this is a single frame or first frame
    frame_type = response[0] & 0xF0
    
    logger.info(f"Frame type: {frame_type}")

    if frame_type == 0x00:  # Single frame
        # Extract the payload length from the first byte
        length = response[0] & 0x0F
        logger.info(f"Single frame with length: {length}")
        
        # Extract the payload (remove the length byte)
        data = response[1:1+length]
        
    elif frame_type == 0x10:  # First frame - start of multi-frame message
        # Calculate total message length from first frame
        length_msb = response[0] & 0x0F
        length_lsb = response[1]
        total_length = (length_msb << 8) | length_lsb
        logger.info(f"First frame of multi-frame message with length: {total_length}")
        
        # Extract data from first frame (bytes 2-7 in the response)
        data = bytearray(response[2:])
        remaining_length = total_length - len(data)
        
        # Send flow control frame to continue receiving
        flow_control = bytearray([0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # CTS, no block limit, no delay
        logger.info(f"Sending flow control: {' '.join(f'{x:02X}' for x in flow_control)}")
        sock.send(bytearray([len(flow_control)]) + flow_control)
        
        # Keep receiving consecutive frames until we have all the data
        sequence = 1
        while remaining_length > 0:
            # Read the next frame
            frame = sock.recv(8)  # Each frame can be up to 8 bytes
            if not frame:
                logger.error("Failed to receive consecutive frame")
                return None
            
            logger.info(f"Received frame: {' '.join(f'{x:02X}' for x in frame)}")
            
            # Verify this is a consecutive frame
            if (frame[0] & 0xF0) != 0x20:
                logger.error(f"Expected consecutive frame but got: 0x{frame[0]:02X}")
                return None
            
            # Extract sequence number from the frame
            received_seq = frame[0] & 0x0F
            logger.info(f"Received consecutive frame with sequence number: {received_seq}")
            
            # Extract data from the consecutive frame (skip the header byte)
            frame_data = frame[1:]
            data.extend(frame_data)
            
            # Update the remaining length
            bytes_received = len(frame_data)
            remaining_length -= bytes_received
            logger.info(f"Received {bytes_received} bytes, {remaining_length} bytes remaining")
            
            # Send another flow control if needed (for block size)
            # This would go here if implementing block size control
            
            sequence = (sequence + 1) & 0x0F  # Wrap around after 15
    else:
        logger.error(f"Unexpected response format: 0x{frame_type:02X}")
        return None
    
    # Check if this is a positive response
    if len(data) > 0 and data[0] == 0x63:  # Positive response for ReadMemoryByAddress
        # Extract the memory data (skip the service ID)
        memory_data = data[1:]
        logger.info(f"Successfully read {len(memory_data)} bytes from memory")
        return memory_data
    elif len(data) >= 3 and data[0] == 0x7F and data[1] == 0x23:
        # Negative response
        error_code = data[2]
        logger.error(f"Negative response with error code: 0x{error_code:02X}")
        if error_code == 0x13:
            logger.error("Security access denied")
        elif error_code == 0x22:
            logger.error("Conditions not correct or request sequence error")
        elif error_code == 0x31:
            logger.error("Request out of range")
        else:
            logger.error(f"Unknown error code: 0x{error_code:02X}")
        return None
    else:
        logger.error(f"Unexpected response format: {' '.join(f'{x:02X}' for x in data)}")
        return None
    
    
TesterPresent(sock) # Hearbeat check for the ecu

ChangeSession(sock, 2)

SecurityAccessGetSeed(sock)

password = b"\x00\x00\x01\x00"
SecurityAccessSendPass(sock, password)

# Now read memory from address 0x4000
print("\n=== Reading Memory from Address 0x4000 ===")

memory_dump = bytearray()
for i in range(0x100, 0x1000, 0x100):
    memory_data = ReadMemoryByAddress(sock, 0x4000 + i, 0x100)  # Read 128 bytes from 0x4000
    memory_dump += memory_data

with open("dump.bin", "wb") as f:
    f.write(memory_dump)

logger.info("Dump written to dump.bin")
sock.close()
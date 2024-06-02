# Load the base TCP protocol analyzer
@load base/protocols/tcp

# Define a new event to handle Modbus packets
event modbus_packet(c: connection, is_orig: bool, seq: count, ack: count, payload: string) &priority=5
{
    print fmt("Modbus packet detected from %s to %s", c$id$orig_h, c$id$resp_h);
}

# Function to check if the packet is a Modbus packet
function is_modbus_packet(payload: string): bool
{
    # Modbus TCP packets typically start with a transaction identifier (2 bytes),
    # protocol identifier (2 bytes, always 0x0000), length (2 bytes), and unit identifier (1 byte).
    # This is a simple check to see if the payload matches these criteria.
    
    if (|payload| < 7) return F;
    
    local transaction_id = bytes_to_count(payload[0:2]);
    local protocol_id = bytes_to_count(payload[2:4]);
    local length = bytes_to_count(payload[4:6]);
    local unit_id = bytes_to_count(payload[6:7]);
    
    # Check if the protocol identifier is 0x0000
    if (protocol_id == 0x0000) return T;
    
    return F;
}

# Event handler for TCP packets
event tcp_packet(c: connection, is_orig: bool, seq: count, ack: count, payload: string)
{
    if (is_modbus_packet(payload))
    {
        # Trigger the modbus_packet event if a Modbus packet is detected
        event modbus_packet(c, is_orig, seq, ack, payload);
    }
}

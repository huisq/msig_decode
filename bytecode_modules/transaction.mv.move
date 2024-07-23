module 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::transaction {
    struct EntryFunction has drop {
        module_name: ModuleId,
        function_name: Identifier,
    }
    
    struct Identifier has drop {
        name: vector<u8>,
    }
    
    struct ModuleId has drop {
        addr: address,
        name: Identifier,
    }
    
    struct RawTransaction has drop {
        sender: address,
        sequence_number: u64,
        payload: TransactionPayload,
        max_gas_amount: u64,
        gas_unit_price: u64,
        expiration_timestamp_secs: u64,
        chain_id: u8,
    }
    
    struct Reader has drop {
        buffer: vector<u8>,
        offset: u64,
    }
    
    struct TransactionPayload has drop {
        type_uleb128: u8,
        payload: 0x1::option::Option<EntryFunction>,
    }
    
    fun decode_address(arg0: &mut Reader) : address {
        0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::utils::address_from_bytes(read(arg0, 32))
    }
    
    fun decode_bytes(arg0: &mut Reader) : vector<u8> {
        let v0 = decode_uleb128(arg0);
        assert!(v0 <= 18446744073709551615, 2);
        read(arg0, v0 as u64)
    }
    
    fun decode_fixed_bytes(arg0: &mut Reader, arg1: u64) : vector<u8> {
        read(arg0, arg1)
    }
    
    public fun decode_transaction(arg0: vector<u8>) : RawTransaction {
        let v0 = reader(arg0);
        let v1 = &mut v0;
        skip(v1, 32);
        let v2 = TransactionPayload{
            type_uleb128 : decode_uleb128_as_u8(v1), 
            payload      : 0x1::option::none<EntryFunction>(),
        };
        let v3 = RawTransaction{
            sender                    : decode_address(v1), 
            sequence_number           : decode_u64(v1), 
            payload                   : v2, 
            max_gas_amount            : 0, 
            gas_unit_price            : 0, 
            expiration_timestamp_secs : 0, 
            chain_id                  : 0,
        };
        if (v3.payload.type_uleb128 == 2) {
            let v4 = Identifier{name: decode_bytes(v1)};
            let v5 = ModuleId{
                addr : decode_address(v1), 
                name : v4,
            };
            let v6 = Identifier{name: decode_bytes(v1)};
            let v7 = EntryFunction{
                module_name   : v5, 
                function_name : v6,
            };
            0x1::option::fill<EntryFunction>(&mut v3.payload.payload, v7);
        };
        set_pos_negative(v1, 24);
        v3.max_gas_amount = decode_u64(v1);
        v3.gas_unit_price = decode_u64(v1);
        v3.expiration_timestamp_secs = decode_u64(v1);
        v3.chain_id = decode_u8(v1);
        v3
    }
    
    fun decode_u64(arg0: &mut Reader) : u64 {
        (decode_u8(arg0) as u64) | (decode_u8(arg0) as u64) << 8 | (decode_u8(arg0) as u64) << 16 | (decode_u8(arg0) as u64) << 24 | (decode_u8(arg0) as u64) << 32 | (decode_u8(arg0) as u64) << 40 | (decode_u8(arg0) as u64) << 48 | (decode_u8(arg0) as u64) << 56
    }
    
    fun decode_u8(arg0: &mut Reader) : u8 {
        let v0 = read(arg0, 1);
        *0x1::vector::borrow<u8>(&v0, 0)
    }
    
    fun decode_uleb128(arg0: &mut Reader) : u128 {
        let v0 = 0;
        let v1 = 0;
        loop {
            let v2 = decode_u8(arg0) as u128;
            let v3 = v0 | (v2 & 127) << v1;
            v0 = v3;
            let v4 = v1 + 7;
            v1 = v4;
            if (v2 & 128 == 0) {
                return v3
            };
            if (v4 < 128) {
            } else {
                break
            };
        };
        abort 2
    }
    
    fun decode_uleb128_as_u8(arg0: &mut Reader) : u8 {
        let v0 = decode_uleb128(arg0);
        assert!(v0 < 256, 2);
        v0 as u8
    }
    
    public fun get_chain_id(arg0: &RawTransaction) : u8 {
        arg0.chain_id
    }
    
    public fun get_expiration_timestamp_secs(arg0: &RawTransaction) : u64 {
        arg0.expiration_timestamp_secs
    }
    
    public fun get_function_name(arg0: &RawTransaction) : vector<u8> {
        0x1::option::borrow<EntryFunction>(&arg0.payload.payload).function_name.name
    }
    
    public fun get_gas_unit_price(arg0: &RawTransaction) : u64 {
        arg0.gas_unit_price
    }
    
    public fun get_max_gas_amount(arg0: &RawTransaction) : u64 {
        arg0.max_gas_amount
    }
    
    public fun get_module_name(arg0: &RawTransaction) : (address, vector<u8>) {
        let v0 = 0x1::option::borrow<EntryFunction>(&arg0.payload.payload);
        (v0.module_name.addr, v0.module_name.name.name)
    }
    
    public fun get_sender(arg0: &RawTransaction) : address {
        arg0.sender
    }
    
    public fun get_sequence_number(arg0: &RawTransaction) : u64 {
        arg0.sequence_number
    }
    
    fun read(arg0: &mut Reader, arg1: u64) : vector<u8> {
        assert!(arg0.offset + arg1 <= 0x1::vector::length<u8>(&arg0.buffer), 1);
        arg0.offset = arg0.offset + arg1;
        0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::utils::vector_slice<u8>(&arg0.buffer, arg0.offset, arg0.offset + arg1)
    }
    
    fun reader(arg0: vector<u8>) : Reader {
        Reader{
            buffer : arg0, 
            offset : 0,
        }
    }
    
    fun set_pos(arg0: &mut Reader, arg1: u64) {
        assert!(arg1 <= 0x1::vector::length<u8>(&arg0.buffer), 1);
        arg0.offset = arg1;
    }
    
    fun set_pos_negative(arg0: &mut Reader, arg1: u64) {
        assert!(arg1 < 0x1::vector::length<u8>(&arg0.buffer), 1);
        arg0.offset = 0x1::vector::length<u8>(&arg0.buffer) - arg1 - 1;
    }
    
    fun skip(arg0: &mut Reader, arg1: u64) {
        assert!(arg0.offset + arg1 <= 0x1::vector::length<u8>(&arg0.buffer), 1);
        arg0.offset = arg0.offset + arg1;
    }
    
    // decompiled from Move bytecode v6
}


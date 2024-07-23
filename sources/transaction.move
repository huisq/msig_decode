/// transaction module is used to decode the essential transaction parameters
/// from the transaction payload.
///
/// The motivation to deserialize the transaction payload is to enforce the data
/// consistency of the transactions to be executed by momentum safe. Instead of
/// let the external caller (CLI / Web application) to input arbitrary transaction
/// parameters, it is more secure and accurate to deserialize the essential
/// transaction parameters from the transaction payload to reduce the vulnerabilities
/// of a malicious momentum safe owner spoofing the wallet by inputing transaction
/// that cannot be executed, which giving legit transaction parameters that pass
/// all checks in move modules.
///
/// The essential transaction parameters to be checked in upper function calls
/// include:
///    1. Sequence number;
///    2. Expiration;
///    3. Gas fees;
/// The parameters are essential since they determines whether a certain transaction
/// can be executed by a momentum safe wallet. If a stale transaction is detected in
/// the move module, the payload checking logic will prevent the certain transaction
/// to be initialized / pruned from account resource data.
///
/// The implementation of this module follows the standard of Aptos transaction
/// serialization / deserialization. You may also check out https://github.com/diem/bcs
/// for original reference of BCS encoding.
module msafe::transaction {
    use std::vector;

    use msafe::utils;
    use std::option::{Self, Option};

    /// Error code of buffer overflow when decoding a transaction
    const EBUFFER_OVERFLOW: u64 = 1;
    /// Error code of buffer overflow when decoding a number
    const ENUMBER_OVERFLOW: u64 = 2;

    /// For BCS transaction, the first 32 bytes of the payload serves as a identifier
    /// to identify itself as a transaction payload. The identifier does not provide
    /// any additional information about the transaction information, and we are safe
    /// to skip these bytes.
    const BCS_SKIP_PAYLOAD_IDENTIFIER_SIZE: u64 = 32;

    /// During BCS deserialization, we will skip deserializing the transaction payload
    /// and directly jump to deserialize the last three u64 from the end of transaction
    /// payload. Three u64 values are expected from the end so we may jump to pos 8 * 3
    /// before the end of payload.
    const BCS_DESERIALIZE_LAST_BUF_SIZE: u64 = 8 * 3;

    /// The size of the address. The size is used for address deserialization from
    /// transaction payload.
    const BCS_ADDRESS_LENGTH: u64 = 32;

    /// TransactionPayload is the transaction payload which defines the on-chain
    /// VM behaviour of executing the transaction.
    /// Currently, only entry function call is supported in Aptos system.
    struct TransactionPayload has drop {
        type_uleb128: u8,
        payload: Option<EntryFunction>,
    }

    /// EntryFunction is the entry function payload in the transaction body.
    /// All external function calls in Aptos system is directly calling an entry
    /// function, E.g. Coin transfer, Account initialization, e.t.c.
    ///
    /// At this moment, the Entry function structure is not fully deserialized
    /// for transaction analysis, since the content in entry function payload
    /// will not effect whether a transaction can be executed in MOVE virtual
    /// machine.
    struct EntryFunction has drop {
        /// Module name is a combination of address and the module name
        module_name: ModuleId,

        /// Function to be called
        function_name: Identifier,

        // Reserved fields for type arguments and arguments.
        // There types do not have a fixed structure. Leave these parameters
        // undeserialized for now.
        // ty_args: vector<vector<u8>>,
        // also skip arguments for its uncertainty in types
        // args: vector<vector<u8>>
    }

    /// ModuleId is a combination of MOVE module deployer and module name.
    /// E.g. addr = @0xmsafe, name = momentum_safe.
    struct ModuleId has drop {
        addr: address,
        name: Identifier
    }

    /// `Identifier` is basically a string decoded from the transaction payload.
    /// The structure is used as both `ModuleId.name` and `EntryFunction.function_name`.
    struct Identifier has drop {
        name: vector<u8>
    }

    /// Deserialized Transaction data structure.
    /// The members in the structure is sorted as the same order as transactions are
    /// serialized with BCS.
    struct RawTransaction has drop {
        sender: address,
        sequence_number: u64,
        payload: TransactionPayload,
        max_gas_amount: u64,
        gas_unit_price: u64,
        expiration_timestamp_secs: u64,
        chain_id: u8,
    }

    /// A helper struct with a target buffer and an offset pointing to the current
    /// buffer position. The struct is used to serialize the transaction payload.
    struct Reader has drop {
        buffer: vector<u8>,
        offset: u64,
    }

    /// Decode the serialized transaction payload to deserialized data structure
    /// `RawTransaction`.
    ///
    /// The deserialization consists of the following process:
    ///     1. Initialize a `Reader` object to scan through the reading buffer.
    ///     2. Skip the first 32 bytes as the identifier of BCS transaction.
    ///     3. Read sender, sequence_number from the buffer.
    ///     4. Read the Transaction payload as Entry function. Note the type arguments
    ///        and function arguments are not serialized since they do not have fixed
    ///        data type and length.
    ///     5. Skip deserializing the type args and function args by jumping to the
    ///        last few bytes before the payload ends.
    ///     6. Deserialize the max_gas_amount, gas_unit_price, expiration_timestamp_secs,
    ///        and chain_id till the end of the payload..
    public fun decode_transaction(buffer: vector<u8>): RawTransaction {
        // Initialize the Reader helper struct.
        let r = &mut reader(buffer);

        // Skip the first 32 bytes of the BCS payload.
        skip(r, BCS_SKIP_PAYLOAD_IDENTIFIER_SIZE);

        // Deserialize from the start of payload.
        let tx = RawTransaction {
            sender: decode_address(r),
            sequence_number: decode_u64(r),
            payload: TransactionPayload {
                type_uleb128: decode_uleb128_as_u8(r),
                payload: option::none(),
            },
            // Empty values. need to be serialized later.
            max_gas_amount: 0,
            gas_unit_price: 0,
            expiration_timestamp_secs: 0,
            chain_id: 0,
        };
        // https://github.com/aptos-labs/aptos-core/blob/d2369dc102b5eb35d2a6c0d91bae7757a4a56a33/ecosystem/typescript/sdk/src/aptos_types/transaction.ts#L351
        // TODO: change to 1 once ModuleBundle has been removed from rust
        // 2 means payload is EntryFunction
        if (tx.payload.type_uleb128 == 2) {
            option::fill(&mut tx.payload.payload, EntryFunction {
                module_name: ModuleId {
                    addr: decode_address(r),
                    name: Identifier {
                        name: decode_bytes(r),
                    },
                },
                function_name: Identifier {
                    name: decode_bytes(r),
                },
            });
        };
        // At this point, we have hit the unfixed type & data length for type
        // args and function args. We will skip deserialize them for now,
        // and jump to the read position of max_gas_amount.
        set_pos_negative(r, BCS_DESERIALIZE_LAST_BUF_SIZE);
        tx.max_gas_amount = decode_u64(r);
        tx.gas_unit_price = decode_u64(r);
        tx.expiration_timestamp_secs = decode_u64(r);
        tx.chain_id = decode_u8(r);

        // All data in transaction is deserialized. Return the result.
        tx
    }

    /// Creates a Reader object to read the buffer from start.
    ///
    /// # Parameters
    /// * `buffer`: Buffer to be read.
    ///
    /// # Returns
    /// * `Reader`: A reader that reads the buffer at the beginning.
    fun reader(
        buffer: vector<u8>
    ): Reader {
        Reader {
            buffer,
            offset: 0,
        }
    }

    /// Set the reader position to the offset before the end of buffer.
    ///
    /// # Parameters
    /// * `r`: Reader to change reading pos.
    /// * `offset`: offset before the end of buffer.
    fun set_pos_negative(
        r: &mut Reader,
        offset: u64
    ) {
        assert!(offset < vector::length(&r.buffer), EBUFFER_OVERFLOW);
        r.offset = vector::length(&r.buffer) - offset - 1;
    }

    /// Set the reader position to the offset from the beginning.
    ///
    /// # Parameters
    /// * `r`: Reader to change pos.
    /// * `offset`: offset after the starting
    fun set_pos(
        r: &mut Reader,
        offset: u64
    ) {
        assert!(offset <= vector::length(&r.buffer), EBUFFER_OVERFLOW);
        r.offset = offset;
    }

    /// Skip a certain length from the current reading position
    /// for the reader.
    ///
    /// # Parameters
    /// * `r`: Reader to change pos.
    /// * `length`: number of bytes to skip.
    fun skip(
        r: &mut Reader,
        length: u64
    ) {
        assert!(r.offset + length <= vector::length(&r.buffer), EBUFFER_OVERFLOW);
        r.offset = r.offset + length;
    }

    /// Read a certain length of data from the current read positon.
    ///
    /// # Parameters
    /// * `r`: Reader for reading data.
    /// * `length`: size of data read from the reader.
    ///
    /// # Returns
    /// * `vector<u8>`: Data read of size length.
    fun read(
        r: &mut Reader,
        length: u64
    ): vector<u8> {
        assert!(r.offset + length <= vector::length(&r.buffer), EBUFFER_OVERFLOW);
        let buffer = utils::vector_slice(&r.buffer, r.offset, r.offset + length);
        r.offset = r.offset + length;
        buffer
    }

    /// Decode the address from the buffer reader. Read exact `BCS_ADDRESS_LENGTH`
    /// data from the buffer and put it into address.
    ///
    /// # Parameters
    /// * `r`: buffer reader.
    ///
    /// # Returns
    /// * `address`: address read from the buffer.
    fun decode_address(
        r: &mut Reader
    ): address {
        utils::address_from_bytes(read(r, BCS_ADDRESS_LENGTH))
    }

    /// Read and decode a byte from the buffer reader as u8.
    ///
    /// # Parameters
    /// * `r`: buffer reader.
    ///
    /// # Returns
    /// * `u8`: u8 read from the buffer.
    fun decode_u8(
        r: &mut Reader
    ): u8 {
        let v = read(r, 1);
        *vector::borrow(&v, 0)
    }

    /// Read and decode a u64 from the buffer reader. Use decode_u8 and bit shift to
    /// decode u64.
    ///
    /// # Parameters
    /// * `r`: buffer reader.
    ///
    /// # Returns
    /// * `u64`: u64 read from the buffer.
    fun decode_u64(
        r: &mut Reader
    ): u64 {
        let v64 = (decode_u8(r) as u64);
        v64 = v64 | ((decode_u8(r) as u64) << 8);
        v64 = v64 | ((decode_u8(r) as u64) << 16);
        v64 = v64 | ((decode_u8(r) as u64) << 24);
        v64 = v64 | ((decode_u8(r) as u64) << 32);
        v64 = v64 | ((decode_u8(r) as u64) << 40);
        v64 = v64 | ((decode_u8(r) as u64) << 48);
        v64 = v64 | ((decode_u8(r) as u64) << 56);
        v64
    }

    /// Read and decode a u128 from the buffer reader. LEB128 is a veriable-length
    /// code compression used to store arbitrary large integers in a small number
    /// of bytes. BCS use unsigned LEB128 to store the size of a bytes object.
    ///
    /// # Parameters
    /// * `r`: buffer reader.
    ///
    /// # Returns
    /// * `u128`: u128 read from the buffer.
    fun decode_uleb128(
        r: &mut Reader
    ): u128 {
        let v128 = 0;
        let off = 0;
        while (true) {
            let v8 = (decode_u8(r) as u128);
            v128 = v128 | ((v8 & 0x7f)<<off);
            off = off + 7;
            if (v8 & 0x80 == 0) {
                break
            };
            assert!(off < 128, ENUMBER_OVERFLOW);
        };
        v128
    }

    /// Read and decode a u8 using the ULEB128 from the buffer reader. The function
    /// will abort with error code ENUMBER_OVERFLOW if the number read overflows
    /// u8.
    ///
    /// # Parameters
    /// * `r`: buffer reader.
    ///
    /// # Returns
    /// * `u8`: u8 deserialized from the read buffer.
    fun decode_uleb128_as_u8(
        r: &mut Reader
    ): u8 {
        let v128 = decode_uleb128(r);
        assert!(v128 < 256, ENUMBER_OVERFLOW);
        (v128 as u8)
    }

    /// Read and decode a fixed size buffer from the buffer reader.
    ///
    /// # Parameters
    /// * `r`: buffer reader.
    /// * `length`: buffer size to be read.
    ///
    /// # Returns
    /// * `vector<u8>`: bytes of fixed length read from the buffer reader.
    fun decode_fixed_bytes(
        r: &mut Reader,
        length: u64
    ): vector<u8> {
        read(r, length)
    }

    /// Read and decode the dynamic sized buffer from the buffer reader.
    /// The length of the bytes is stored as ULEB128 as the first parameter in the
    /// buffer. First deserialize the buffer length, and then read the buffer
    /// of the given length.
    ///
    /// # Parameters
    /// * `r`: buffer reader.
    ///
    /// # Returns
    /// * `vector<u8>`: bytes read from the buffer reader.
    fun decode_bytes(
        r: &mut Reader
    ): vector<u8> {
        let raw_number = decode_uleb128(r);
        assert!(raw_number <= 0xffffffffffffffff, ENUMBER_OVERFLOW);
        let length = (raw_number as u64);
        read(r, length)
    }

    /// Return the sender from the deserialize transaction
    ///
    /// # Parameters
    /// * `tx`: Deserialized transactions.
    ///
    /// # Returns
    /// * `address`: sender address.
    public fun get_sender(
        tx: &RawTransaction
    ): address {
        tx.sender
    }

    /// Return the sequence number from the deserialize transaction
    ///
    /// # Parameters
    /// * `tx`: Deserialized transactions.
    ///
    /// # Returns
    /// * `u64`: sequence number.
    public fun get_sequence_number(
        tx: &RawTransaction
    ): u64 {
        tx.sequence_number
    }

    /// Return the expiration timestamp from the deserialize transaction
    ///
    /// # Parameters
    /// * `tx`: Deserialized transactions.
    ///
    /// # Returns
    /// * `u64`: expiration timestamp.
    public fun get_expiration_timestamp_secs(
        tx: &RawTransaction
    ): u64 {
        tx.expiration_timestamp_secs
    }

    /// Return the max gas from the deserialize transaction
    ///
    /// # Parameters
    /// * `tx`: Deserialized transactions.
    ///
    /// # Returns
    /// * `u64`: max gas.
    public fun get_max_gas_amount(
        tx: &RawTransaction
    ): u64 {
        tx.max_gas_amount
    }

    /// Return the gas price from the deserialize transaction
    ///
    /// # Parameters
    /// * `tx`: Deserialized transactions.
    ///
    /// # Returns
    /// * `u64`: gas unit price.
    public fun get_gas_unit_price(
        tx: &RawTransaction
    ): u64 {
        tx.gas_unit_price
    }

    /// Return the chain ID from the deserialize transaction
    ///
    /// # Parameters
    /// * `tx`: Deserialized transactions.
    ///
    /// # Returns
    /// * `u8`: chain ID.
    public fun get_chain_id(
        tx: &RawTransaction
    ): u8 {
        tx.chain_id
    }

    /// Return the module ID from the deserialize transaction
    ///
    /// # Parameters
    /// * `tx`: Deserialized transactions.
    ///
    /// # Returns
    /// * `address`: deployer of the move module.
    /// * `vector<u8>`: module name.
    public fun get_module_name(
        tx: &RawTransaction
    ): (address, vector<u8>) {
        let payload = option::borrow(&tx.payload.payload);
        (payload.module_name.addr, payload.module_name.name.name)
    }

    /// Return the function name from the deserialize transaction
    ///
    /// # Parameters
    /// * `tx`: Deserialized transactions.
    ///
    /// # Returns
    /// * `vector<u8>`: function name.
    public fun get_function_name(
        tx: &RawTransaction
    ): vector<u8> {
        option::borrow(&tx.payload.payload).function_name.name
    }

    /// default error code for unit test
    const E: u64 = 0;

    #[test]
    /// Test the transaction deserialization from a pre-defined transaction payload.
    fun test_decode_transaction() {
        // Deserialize from a pre-defined payload for a coin transfer transaction.
        let payload = x"b5e97db07fa0bd0e5598aa3643a9bc6f6693bddc1a9fec9e674a461eaa00b1937f9ef3ef57ee908deddb8ca84ed126f413d1a6265b3b73a28d645d36403be31c000000000000000002854e9c2ca1a2d068b79ee1f04ff2daaab764bd51f157734a11c2ceae3727d66e0d6d6f6d656e74756d5f7361666508726567697374657200010d0c68656c6c6f206d2d73616665d00700000000000001000000000000000e341f63000000001b";
        let tx = decode_transaction(payload);

        // Check the results
        assert!(get_sender(&tx) == @0x7f9ef3ef57ee908deddb8ca84ed126f413d1a6265b3b73a28d645d36403be31c, E);
        assert!(get_sequence_number(&tx) == 0, E);
        assert!(get_chain_id(&tx) == 27, E);
        assert!(get_max_gas_amount(&tx) == 2000, E);
        assert!(get_gas_unit_price(&tx) == 1, E);
        assert!(get_expiration_timestamp_secs(&tx) == 1662989326, E);
        let (module_addr, module_name) = get_module_name(&tx);
        assert!(module_addr == @0x854e9c2ca1a2d068b79ee1f04ff2daaab764bd51f157734a11c2ceae3727d66e, E);
        assert!(module_name == b"momentum_safe", E);
        assert!(get_function_name(&tx) == b"register", E);
    }

    #[test]
    /// Test reader operation including
    ///     1. read
    ///     2. set_pos
    ///     3. set_pos_negative
    ///     4. skip
    fun test_reader() {
        let r = &mut reader(x"00010203040506070809");
        let i = 0u8;
        while (i < 10) {
            assert!(read(r, 1) == vector<u8>[i], E);
            i = i + 1;
        };
        i = 0;
        while (i < 10) {
            set_pos(r, (i as u64));
            assert!(read(r, 1) == vector<u8>[i], E);
            i = i + 1;
        };
        i = 0;
        while (i < 10) {
            set_pos_negative(r, (i as u64));
            assert!(read(r, 1) == vector<u8>[9 - i], E);
            i = i + 1;
        };
        set_pos(r, 0);
        skip(r, 5);
        assert!(read(r, 1) == vector<u8>[5], E)
    }


    #[test]
    #[expected_failure(abort_code = EBUFFER_OVERFLOW)]
    /// Test the scenario where the reader will abort in buffer overflow.
    /// The buffer size is smaller than the target read size.
    fun test_reader_overflow() {
        let r = &mut reader(x"00010203040506070809");
        read(r, 11);
    }

    #[test]
    /// Test decoding an address from buffer
    fun test_decode_address() {
        let r = &mut reader(x"7f9ef3ef57ee908deddb8ca84ed126f413d1a6265b3b73a28d645d36403be31c");
        let got = decode_address(r);
        let expected = @0x7f9ef3ef57ee908deddb8ca84ed126f413d1a6265b3b73a28d645d36403be31c;
        assert!(got == expected, E);
    }

    #[test]
    #[expected_failure(abort_code = EBUFFER_OVERFLOW)]
    /// Test decoding a buffer smaller than address size
    fun test_decode_address_overflow() {
        let r = &mut reader(x"7f9ef3ef57ee908deddb8ca84ed126f413d1a6265b3b73a28d");
        decode_address(r);
    }

    #[test]
    /// Test coding a series of u8 from buffer
    fun test_decode_u8() {
        let r = &mut reader(x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let i = 0;
        while (i < 256) {
            let expected = i;
            let got = decode_u8(r);
            assert!(got == (expected as u8), E);
            i = i + 1;
        }
    }

    #[test]
    /// Test decoding two u64 from a buffer
    fun test_decode_u64() {
        let r = &mut reader(x"efcdab89674523011032547698badcfe");
        assert!(decode_u64(r) == 0x0123456789abcdef, E);
        assert!(decode_u64(r) == 0xfedcba9876543210, E);
    }

    #[test]
    #[expected_failure(abort_code = EBUFFER_OVERFLOW)]
    /// Test u64 decode from a buffer with overflow.
    fun test_decode_u64_overflow() {
        let r = &mut reader(x"efcdab8967452301103257");
        decode_u64(r);
        decode_u64(r);
    }

    #[test]
    /// Test several uleb128 decode calls from a buffer.
    fun test_decode_uleb128() {
        let r = &mut reader(x"ffffffffffffffffffffffffffffffffffff0fffffffff0f0001f8acd1910198f5f2f60f");
        assert!(decode_uleb128(r) == 0xffffffffffffffffffffffffffffffff, E);
        assert!(decode_uleb128(r) == 0xffffffff, E);
        assert!(decode_uleb128(r) == 0x0, E);
        assert!(decode_uleb128(r) == 0x1, E);
        assert!(decode_uleb128(r) == 0x12345678, E);
        assert!(decode_uleb128(r) == 0xfedcba98, E);
    }

    #[test]
    #[expected_failure(abort_code = ENUMBER_OVERFLOW)]
    /// Test the scenario where there is not enough bytes to read
    fun test_decode_uleb128_overflow() {
        let r = &mut reader(x"ffffffffffffffffffffffffffffffffffffff");
        decode_uleb128(r);
    }

    #[test]
    /// test decode_uleb128_as_u8
    fun test_decode_uleb128_as_u8() {
        let r = &mut reader(x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80018101820183018401850186018701880189018a018b018c018d018e018f0190019101920193019401950196019701980199019a019b019c019d019e019f01a001a101a201a301a401a501a601a701a801a901aa01ab01ac01ad01ae01af01b001b101b201b301b401b501b601b701b801b901ba01bb01bc01bd01be01bf01c001c101c201c301c401c501c601c701c801c901ca01cb01cc01cd01ce01cf01d001d101d201d301d401d501d601d701d801d901da01db01dc01dd01de01df01e001e101e201e301e401e501e601e701e801e901ea01eb01ec01ed01ee01ef01f001f101f201f301f401f501f601f701f801f901fa01fb01fc01fd01fe01ff01");
        let i = 0;
        while (i < 256) {
            let expected = i;
            let got = decode_uleb128_as_u8(r);
            assert!(got == (expected as u8), E);
            i = i + 1;
        }
    }

    #[test]
    #[expected_failure(abort_code = ENUMBER_OVERFLOW)]
    /// testdecode_uleb128_as_u8 where the result overflows u8
    fun test_decode_uleb128_as_u8_overflow() {
        let r = &mut reader(x"ff02");
        decode_uleb128_as_u8(r);
    }

    #[test]
    /// test decode_fixed_bytes
    fun test_decode_fixed_bytes() {
        let expected = x"7f9ef3ef57ee908deddb8ca84ed126f413d1a6265b3b73a28d645d36403be31c";
        let r = &mut reader(expected);
        let got = decode_fixed_bytes(r, vector::length(&expected));
        assert!(got == expected, E);
    }

    #[test]
    /// test decode_fixed_bytes
    fun test_decode_bytes() {
        let expected = x"7f9ef3ef57ee908deddb8ca84ed126f413d1a6265b3b73a28d645d36403be31c";
        let r = &mut reader(x"207f9ef3ef57ee908deddb8ca84ed126f413d1a6265b3b73a28d645d36403be31c");
        let got = decode_bytes(r);
        assert!(got == expected, E);
    }

    #[test]
    #[expected_failure(abort_code = EBUFFER_OVERFLOW)]
    /// Test decode_bytes where there is not enough bytes data.
    fun test_decode_bytes_bytes_overflow() {
        let r = &mut reader(x"207f");
        decode_bytes(r);
    }

    #[test]
    #[expected_failure(abort_code = ENUMBER_OVERFLOW)]
    /// Test decode_bytes where the length overflows u64.
    fun test_decode_bytes_size_overflow() {
        let r = &mut reader(x"fffffffffffffffff01234");
        decode_bytes(r);
    }
}

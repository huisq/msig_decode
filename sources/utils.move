/// Utils library support for momentum safe.
/// Includes cryptographic and dependency functions.
module msafe::utils {
    use std::bcs;
    use std::hash;
    use std::vector;
    use std::option;

    use aptos_framework::timestamp;
    use aptos_framework::util;
    use aptos_std::ed25519;
    use aptos_std::simple_map::{Self, SimpleMap};

    use msafe::table_map::{Self, TableMap};

    /// Derive the authentication key from Ed25519 public key.
    ///
    /// The authentication key is the SHA3-256 hash of the public key bytes.
    ///
    ///     auth_key = sha3-256(public_key | 0x00)
    ///
    /// Where the trending 0x00 is a schema identifier for single signed wallet.
    ///
    /// When using momentum safe, we require the derived auth key match
    /// the auth key stored in `Account`. Otherwise, the address will lose
    /// his control over the momentum safe wallet.
    ///
    /// # Parameters
    /// * `public_key`: ed25519 public key for single signed wallet
    ///
    /// # Returns
    /// * `vector<u8>`: derived authentication key
    public fun derive_auth_key(
        public_key: vector<u8>
    ): vector<u8> {
        let pk_bytes = copy public_key;
        vector::push_back(&mut pk_bytes, 0);
        hash::sha3_256(pk_bytes)
    }

    /// Calculate aptos multi-ed25519 authorizon key.
    ///
    /// The default scheme of Aptos multi-ed25519 public key is:
    ///
    ///    auth_key = sha3-256(pk_a | pk_b | pk_c | ... | threshold | 0x01)
    ///
    /// Where pk_* is the public key of the owner, threshold is the required signature
    /// threshold for the multi-sig tranaction. Lastly, the trailing 0x01 is the
    /// identifier for multi-ed25519 schema.
    ///
    /// Momentum Safe is built on top of Aptos native multi-ed25519 implementation,
    /// and add a minor mutation on Aptos multi-ed25519 public key computation:
    ///
    ///    auth_key = sha3-256(pk_a | pk_b | pk_c | ... | pk_nonce | threshold | 0x01)
    ///
    /// The additional pk_nonce is a prefix with a little endian encoding of the nonce
    /// associated with the address holding the first public key pk_a. pk_a has two
    /// components:
    ///
    ///     1. A prefix of the first 16 bytes of the deployer address, serving as a
    ///         identifier from momentum safe modules.
    ///     2. A nonce, serving as a counter to identify the multiple multi-sig wallet
    ///         accounts created by the same group of owners. The nonce of the first
    ///         owner will automatically increment when a new wallet creation request
    ///         is received.
    ///
    /// Since the private key of the nonce as public key can never be acquired as a premise
    /// of cryptography, the public key schema has the same interpretation as the Aptos
    /// native multi-ed25519 public key computation.
    ///
    /// # Parameters
    /// * `pubkeys`: public keys for the multi-sig owners
    /// * `threshold`: signing threshold for multi-sig transaction
    /// * `nonce`: the counter used to identify different multi-sig for the same
    ///            owners
    /// * `module_address`: module_address used to generate public key with the nonce.
    ///
    /// # Returns
    /// * `vector<u8>`: authentication key computed for multi-ed25519 account
    public fun derive_multisig_auth_key(
        pubkeys: vector<vector<u8>>,
        threshold: u8,
        nonce: u64,
        module_address: address
    ): vector<u8> {
        // Write the additional nonce as the last public key.
        vector::push_back(&mut pubkeys, nonce_to_public_key(nonce, module_address));
        multisig_public_keys_to_auth_key(pubkeys, threshold)
    }

    /// Calculate aptos multi-ed25519 authorizon key by public keys and threshold.
    public fun multisig_public_keys_to_auth_key(pubkeys: vector<vector<u8>>, threshold: u8): vector<u8> {
        // Write the owner public keys to buffer.
        let pk_bytes = vector::empty<u8>();
        let i = 0;
        while (i < vector::length(&pubkeys)) {
            vector::append(&mut pk_bytes, *vector::borrow(&pubkeys, i));
            i = i + 1;
        };

        // Write signature threshold and multi-ed25519 schema identifier.
        vector::push_back(&mut pk_bytes, threshold);
        vector::push_back(&mut pk_bytes, 1);

        // Derive the authentication key from the buffer.
        hash::sha3_256(pk_bytes)
    }

    /// Verify the ed25519 signature signed by a simple wallet against signed message
    /// corresponding public key. Directly call aptos_framework function
    /// `ed25519::signature_verify_strict`.
    ///
    /// # Parameters
    /// * `signature`: signature to be verified
    /// * `public_key`: public key of the signer
    /// * `message`: signed message
    ///
    /// # Returns
    /// * `bool`: whether the signature verification passes
    public fun verify_signature(
        signature: vector<u8>,
        public_key: vector<u8>,
        message: vector<u8>
    ): bool {
        ed25519::signature_verify_strict(
            &ed25519::new_signature_from_bytes(signature),
            &ed25519::new_unvalidated_public_key_from_bytes(public_key),
            message
        )
    }

    /// Warpped system call to convert a byte to an address.
    /// If the system function interface changes, we just change here.
    ///
    /// # Parameter
    /// * `bytes`: bytes to be converted to the address
    ///
    /// # Returns
    /// * `address`: converted address
    public fun address_from_bytes(
        bytes: vector<u8>
    ): address {
        util::address_from_bytes(bytes)
    }

    /// Warpped system call to for the system timestamp.
    /// If the system function interface changes, we just change here.
    ///
    /// # Returns
    /// * `u64`: current timestamp in seconds
    public fun now_seconds(): u64 {
        timestamp::now_seconds()
    }

    /// check if a vector has duplicate elements.
    ///
    /// # Parameters
    /// * `vec`: vector to check
    ///
    /// # Return
    /// * `bool`: true if has duplicate elements else false.
    public fun vector_dup_exist<T: copy + drop>(vec: &vector<T>): bool {
        let vec_exists = vector::empty<T>();
        let i = 0;
        while (i < vector::length(vec)) {
            let elem = vector::borrow(vec, i);
            if (vector::contains(&vec_exists, elem)) {
                return true
            };
            vector::push_back(&mut vec_exists, *elem);
            i = i + 1;
        };
        false
    }

    /// Return the subslice of the vector, starting at start, and end (exclusive)
    /// at end index.
    ///
    /// # Parameters
    /// * `vec`: The original vector to operate on.
    /// * `start`: The start index of the sub-vector.
    /// * `end`: The end index (exclusive) of the sub-vector.
    ///
    /// # Returns
    /// * `vector<T>`: The sub-vector of the given vector.
    public fun vector_slice<T: copy>(vec: &vector<T>, start: u64, end: u64): vector<T> {
        let vec_slice = vector::empty<T>();
        while (start < end) {
            vector::push_back(&mut vec_slice, *vector::borrow(vec, start));
            start = start + 1;
        };
        vec_slice
    }

    /// Return the nonce prefix (the first 16 bytes of the deployer address)
    ///
    /// # Returns
    /// * A vector of the 16 bytes of the deployer address.
    fun nonce_prefix(module_address: address): vector<u8> {
        let prefix32 = bcs::to_bytes(&module_address);
        vector_slice(&prefix32, 0, 16)
    }

    /// nonce_to_public_key convert a nonce to public key.
    /// The nonce serves as a identifier for the momentum safe wallet creation.
    /// It is added to multi-ed25519 public key as the last owner public key.
    /// The encoding is using a prefix of the deployment address with a little
    /// endian as suggested in BCS serialization.
    ///
    /// # Parameters
    /// * `nonce`: counter to be converted to public key
    /// * `module_address`: module_address used to generate public key with the nonce.
    ///
    /// # Returns
    /// * `vector<u8>`: Public key converted
    fun nonce_to_public_key(
        nonce: u64,
        module_address: address
    ): vector<u8> {
        let pk_bytes = nonce_prefix(module_address);
        // little endian
        vector::append(&mut pk_bytes, bcs::to_bytes(&(nonce as u128)));
        pk_bytes
    }

    /// next_valid_nonce_public_key srearch next valid nonce public key
    ///
    /// # Parameters
    /// * `cur_nonce`: nonce to start search
    /// * `module_address`: module_address used to generate public key with the nonce.
    ///
    /// # Returns
    /// * `u64`: next valid nonce, abort if can find it in 256 times.
    public fun next_valid_nonce_public_key(cur_nonce: u64, module_address: address): u64 {
        // According to our stress test, the probability of a valid public key is about 50%.
        // The probability of not finding it 256 times is about the same as the probability of guessing the private key at random.
        let search_end = cur_nonce + 256;
        while (cur_nonce < search_end) {
            let pk_bytes = nonce_to_public_key(cur_nonce, module_address);
            if (is_public_key_valid(pk_bytes)) {
                return cur_nonce
            };
            cur_nonce = cur_nonce + 1;
        };
        abort (0)
    }

    public fun is_public_key_valid(pk_bytes: vector<u8>): bool {
        let pk = ed25519::new_validated_public_key_from_bytes(pk_bytes);
        option::is_some(&pk)
    }

    /// check if a vector starts with a prefix.
    public fun starts_with(bytes: vector<u8>, prefix: vector<u8>): bool {
        let prefix_len = vector::length(&prefix);
        if (vector::length(&bytes) < prefix_len) {
            return false
        };
        let i = 0;
        while (i < vector::length(&prefix)) {
            let byte_a = vector::borrow(&bytes, i);
            let byte_b = vector::borrow(&prefix, i);
            if (byte_a != byte_b) {
                return false
            };
            i = i + 1;
        };
        true
    }

    /// convert a table map to simple map
    public fun table_map_to_simple_map<K: copy + store + drop, V: copy + store + drop>(
        map: &TableMap<K, V>
    ): SimpleMap<K, V> {
        let reuslt = simple_map::create<K, V>();
        let i = 0;
        while (i < table_map::length(map)) {
            let (key, value) = table_map::at(map, i);
            simple_map::upsert(&mut reuslt, *key, *value);
            i = i + 1;
        };
        reuslt
    }

    #[test_only]
    /// default error code for unit test
    const E: u64 = 0;

    #[test]
    fun test_is_public_key_valid() {
        assert!(is_public_key_valid(x"0200000000000000000000000000000000000000000000000000000000000000") == false, E);
        assert!(is_public_key_valid(x"70592029ca79eb2286cb2ed8ba04e2a4e0d55be1dc9c9bfa27651de8eaec03f3") == true, E);
    }

    #[test]
    /// Test derive_multisig_auth_key.
    /// Test data offered here is pre-calculated result.
    fun test_derive_multisig_auth_key() {
        let public_keys = vector<vector<u8>>
            [
                x"fb2c62d2ab98f1e6454a83ec0b7a2102a3d6b84d6c6d89ec013ba544f823345a",
                x"f35efdbaf43b84fde165722ec0bf0677c2aa3c4e682ad09dae57ffeaf6351b2d",
                x"2c7a0e2b666900dbcca041516cdda75e57fffc06a1103cd4da21f026f1ab63b5",
            ];
        let expected = x"c0455c582b0e3d794918db7de1f1c218ac311701db218958718e74494703fd3b";
        let got = derive_multisig_auth_key(public_keys, 2, 0, @test_msafe_module);
        assert!(got == expected, E);
    }

    #[test]
    /// Test verify signature.
    /// Test data offered here is from a pre-calculated result.
    fun test_verify_signature() {
        let signing_data = x"b5e97db07fa0bd0e5598aa3643a9bc6f6693bddc1a9fec9e674a461eaa00b1937f9ef3ef57ee908deddb8ca84ed126f413d1a6265b3b73a28d645d36403be31c000000000000000002854e9c2ca1a2d068b79ee1f04ff2daaab764bd51f157734a11c2ceae3727d66e0d6d6f6d656e74756d5f7361666508726567697374657200010d0c68656c6c6f206d2d73616665d00700000000000001000000000000000e341f63000000001b";
        let signature = x"be21853ae48f0858d3275053154b4d29a85559378efdba6eddea7ea3d36c6365f335c4f66fca36f92a723b927f2eb9b6dad60a9ebec3f4cf6bcff6594640730e";
        let public_key = x"8e3aab10b4a03120ac5cb774b3ec5e0de6a8f79467b10ec03e46ec14b08c0e00";
        assert!(verify_signature(signature, public_key, signing_data), E);
    }

    #[test]
    /// Test derive_auth_key.
    /// Test data offered here is from a pre-calculated result.
    fun test_derive_auth_key() {
        let public_keys = vector<vector<u8>>
            [
                x"8e3aab10b4a03120ac5cb774b3ec5e0de6a8f79467b10ec03e46ec14b08c0e00",
                x"230960583112a0d9d90f5224384781b2bfc1a1522c1c006ba2c4d05950135251",
                x"d8ac60a9df545dab6610bf9522363896c22c61d2c9353bef0c9e0217b6a598be",
            ];
        let expected_auth_keys = vector<vector<u8>>
            [
                x"b9bf751743504188d77e9abfbb550f604b6e5f15cf1ff46bde819190a3f42955",
                x"eafebdf8e928acea23ae053785b156cc7dd8164e8f6c5c07c69400c0d094a0e9",
                x"91f8ac84d78610367802596ced4770b59a0cbb7109427aabe5dfd839f5e7f87d",
            ];
        let i = 0;
        while (i < vector::length(&public_keys)) {
            let public_key = *vector::borrow(&public_keys, i);
            let got = derive_auth_key(public_key);
            let expected = *vector::borrow(&expected_auth_keys, i);
            assert!(got == expected, E);
            i = i + 1;
        };
    }

    #[test]
    fun test_address_from_bytes() {
        let addresses_bytes = vector<vector<u8>>
            [
                x"b9bf751743504188d77e9abfbb550f604b6e5f15cf1ff46bde819190a3f42955",
                x"eafebdf8e928acea23ae053785b156cc7dd8164e8f6c5c07c69400c0d094a0e9",
                x"91f8ac84d78610367802596ced4770b59a0cbb7109427aabe5dfd839f5e7f87d",
                x"b9bf751743504188d77e9abfbb550f604b6e5f15cf1ff46bde819190a3f42955",
            ];
        let expected_addresses = vector<address>
            [
                @0xb9bf751743504188d77e9abfbb550f604b6e5f15cf1ff46bde819190a3f42955,
                @0xeafebdf8e928acea23ae053785b156cc7dd8164e8f6c5c07c69400c0d094a0e9,
                @0x91f8ac84d78610367802596ced4770b59a0cbb7109427aabe5dfd839f5e7f87d,
                @0xb9bf751743504188d77e9abfbb550f604b6e5f15cf1ff46bde819190a3f42955,
            ];
        let i = 0;
        while (i < vector::length(&addresses_bytes)) {
            let address_bytes = *vector::borrow(&addresses_bytes, i);
            let got = address_from_bytes(address_bytes);
            let expected = *vector::borrow(&expected_addresses, i);
            assert!(got == expected, E);
            i = i + 1;
        };
    }

    #[test]
    #[expected_failure]
    /// Test the failed case for the input public key bytes overflows the size of public
    /// key (32)
    fun test_address_from_bytes_overflow() {
        // Address overflow
        let address_byte = x"b9bf751743504188d77e9abfbb550f604b6e5f15cf1ff46bde819190a3f42955aaaaaa";
        let _ = address_from_bytes(address_byte);
    }


    #[test]
    fun test_vector_u8_slice() {
        let vec = b"0123456789";
        assert!(vector_slice(&vec, 3, 8) == b"34567", E)
    }

    #[test]
    #[expected_failure]
    fun test_vector_u8_slice_failed() {
        let vec = b"0123456789";
        vector_slice(&vec, 3, 100);
    }

    #[test]
    fun test_nonce_to_public_key() {
        assert!(
            nonce_to_public_key(
                0x00,
                @test_msafe_module
            ) == x"4cebef114d8ce88cc1e1df73b9a6effa00000000000000000000000000000000",
            E
        );
        assert!(
            nonce_to_public_key(
                0x01,
                @test_msafe_module
            ) == x"4cebef114d8ce88cc1e1df73b9a6effa01000000000000000000000000000000",
            E
        );
        assert!(
            nonce_to_public_key(
                0x0123456789abcdef,
                @test_msafe_module
            ) == x"4cebef114d8ce88cc1e1df73b9a6effaefcdab89674523010000000000000000",
            E
        );
        assert!(
            nonce_to_public_key(
                0xfedcba9876543210,
                @test_msafe_module
            ) == x"4cebef114d8ce88cc1e1df73b9a6effa1032547698badcfe0000000000000000",
            E
        );
    }

    #[test]
    fun test_vector_dup_check() {
        assert!(vector_dup_exist(&b"0123456789") == false, E);
        assert!(vector_dup_exist(&b"0123456780") == true, E);
    }
}

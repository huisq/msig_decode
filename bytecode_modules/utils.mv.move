module 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::utils {
    public fun now_seconds() : u64 {
        0x1::timestamp::now_seconds()
    }
    
    public fun address_from_bytes(arg0: vector<u8>) : address {
        0x1::util::address_from_bytes(arg0)
    }
    
    public fun derive_auth_key(arg0: vector<u8>) : vector<u8> {
        let v0 = arg0;
        0x1::vector::push_back<u8>(&mut v0, 0);
        0x1::hash::sha3_256(v0)
    }
    
    public fun derive_multisig_auth_key(arg0: vector<vector<u8>>, arg1: u8, arg2: u64, arg3: address) : vector<u8> {
        0x1::vector::push_back<vector<u8>>(&mut arg0, nonce_to_public_key(arg2, arg3));
        multisig_public_keys_to_auth_key(arg0, arg1)
    }
    
    public fun is_public_key_valid(arg0: vector<u8>) : bool {
        let v0 = 0x1::ed25519::new_validated_public_key_from_bytes(arg0);
        0x1::option::is_some<0x1::ed25519::ValidatedPublicKey>(&v0)
    }
    
    public fun multisig_public_keys_to_auth_key(arg0: vector<vector<u8>>, arg1: u8) : vector<u8> {
        let v0 = 0x1::vector::empty<u8>();
        let v1 = 0;
        while (v1 < 0x1::vector::length<vector<u8>>(&arg0)) {
            0x1::vector::append<u8>(&mut v0, *0x1::vector::borrow<vector<u8>>(&arg0, v1));
            v1 = v1 + 1;
        };
        0x1::vector::push_back<u8>(&mut v0, arg1);
        0x1::vector::push_back<u8>(&mut v0, 1);
        0x1::hash::sha3_256(v0)
    }
    
    public fun next_valid_nonce_public_key(arg0: u64, arg1: address) : u64 {
        while (arg0 < arg0 + 256) {
            if (is_public_key_valid(nonce_to_public_key(arg0, arg1))) {
                return arg0
            };
            arg0 = arg0 + 1;
        };
        abort 0
    }
    
    fun nonce_prefix(arg0: address) : vector<u8> {
        let v0 = 0x1::bcs::to_bytes<address>(&arg0);
        vector_slice<u8>(&v0, 0, 16)
    }
    
    fun nonce_to_public_key(arg0: u64, arg1: address) : vector<u8> {
        let v0 = nonce_prefix(arg1);
        let v1 = arg0 as u128;
        0x1::vector::append<u8>(&mut v0, 0x1::bcs::to_bytes<u128>(&v1));
        v0
    }
    
    public fun starts_with(arg0: vector<u8>, arg1: vector<u8>) : bool {
        if (0x1::vector::length<u8>(&arg0) < 0x1::vector::length<u8>(&arg1)) {
            return false
        };
        let v0 = 0;
        while (v0 < 0x1::vector::length<u8>(&arg1)) {
            if (0x1::vector::borrow<u8>(&arg0, v0) != 0x1::vector::borrow<u8>(&arg1, v0)) {
                return false
            };
            v0 = v0 + 1;
        };
        true
    }
    
    public fun table_map_to_simple_map<T0: copy + drop + store, T1: copy + drop + store>(arg0: &0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::TableMap<T0, T1>) : 0x1::simple_map::SimpleMap<T0, T1> {
        let v0 = 0x1::simple_map::create<T0, T1>();
        let v1 = 0;
        while (v1 < 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::length<T0, T1>(arg0)) {
            let (v2, v3) = 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::at<T0, T1>(arg0, v1);
            let (_, _) = 0x1::simple_map::upsert<T0, T1>(&mut v0, *v2, *v3);
            v1 = v1 + 1;
        };
        v0
    }
    
    public fun vector_dup_exist<T0: copy + drop>(arg0: &vector<T0>) : bool {
        let v0 = 0x1::vector::empty<T0>();
        let v1 = 0;
        while (v1 < 0x1::vector::length<T0>(arg0)) {
            let v2 = 0x1::vector::borrow<T0>(arg0, v1);
            if (0x1::vector::contains<T0>(&v0, v2)) {
                return true
            };
            0x1::vector::push_back<T0>(&mut v0, *v2);
            v1 = v1 + 1;
        };
        false
    }
    
    public fun vector_slice<T0: copy>(arg0: &vector<T0>, arg1: u64, arg2: u64) : vector<T0> {
        let v0 = 0x1::vector::empty<T0>();
        while (arg1 < arg2) {
            0x1::vector::push_back<T0>(&mut v0, *0x1::vector::borrow<T0>(arg0, arg1));
            arg1 = arg1 + 1;
        };
        v0
    }
    
    public fun verify_signature(arg0: vector<u8>, arg1: vector<u8>, arg2: vector<u8>) : bool {
        let v0 = 0x1::ed25519::new_signature_from_bytes(arg0);
        let v1 = 0x1::ed25519::new_unvalidated_public_key_from_bytes(arg1);
        0x1::ed25519::signature_verify_strict(&v0, &v1, arg2)
    }
    
    // decompiled from Move bytecode v6
}


module msafe::creator {
    struct CreateWalletTxn has copy, drop, store {
        payload: vector<u8>,
        signatures: 0x1::simple_map::SimpleMap<vector<u8>, vector<u8>>,
    }
    
    struct MomentumSafeCreation has copy, drop, store {
        owners: vector<address>,
        public_keys: vector<vector<u8>>,
        nonce: u64,
        threshold: u8,
        txn: CreateWalletTxn,
    }
    
    struct MultiSigCreationEvent has key {
        events: 0x1::event::EventHandle<MomentumSafeCreation>,
    }
    
    struct PendingMultiSigCreations has key {
        nonces: 0x1::table::Table<address, u64>,
        creations: 0x1::table::Table<address, MomentumSafeCreation>,
    }
    
    fun verify_signature(arg0: vector<u8>, arg1: vector<u8>, arg2: vector<u8>) {
        assert!(msafe::utils::verify_signature(arg0, arg1, arg2), 1);
    }
    
    fun add_signature(arg0: &mut MomentumSafeCreation, arg1: u8, arg2: vector<u8>) {
        let v0 = *0x1::vector::borrow<vector<u8>>(&arg0.public_keys, arg1 as u64);
        verify_signature(arg2, v0, arg0.txn.payload);
        0x1::simple_map::add<vector<u8>, vector<u8>>(&mut arg0.txn.signatures, v0, arg2);
    }
    
    fun add_to_registry(arg0: &vector<address>, arg1: address) {
        msafe::registry::register_msafe(arg0, arg1, true);
    }
    
    public entry fun clean_expired_creation(arg0: vector<address>) acquires PendingMultiSigCreations {
        while (!0x1::vector::is_empty<address>(&arg0)) {
            let (_, v1) = remove_wallet_creation(0x1::vector::pop_back<address>(&mut arg0));
            let v2 = v1;
            let v3 = msafe::transaction::decode_transaction(v2.txn.payload);
            assert!(msafe::transaction::get_expiration_timestamp_secs(&v3) < msafe::utils::now_seconds(), 8);
        };
    }
    
    fun derive_new_multisig_auth_key(arg0: &mut PendingMultiSigCreations, arg1: address, arg2: vector<vector<u8>>, arg3: u8, arg4: address) : (address, u64) {
        if (!0x1::table::contains<address, u64>(&arg0.nonces, arg1)) {
            0x1::table::add<address, u64>(&mut arg0.nonces, arg1, msafe::utils::next_valid_nonce_public_key(0, arg4));
        };
        let v0 = 0x1::table::borrow_mut<address, u64>(&mut arg0.nonces, arg1);
        let v1 = *v0;
        *v0 = msafe::utils::next_valid_nonce_public_key(v1 + 1, arg4);
        (msafe::utils::address_from_bytes(msafe::utils::derive_multisig_auth_key(arg2, arg3, v1, arg4)), v1)
    }
    
    public fun get_creation(arg0: address) : (vector<address>, vector<vector<u8>>, u64, u8) acquires PendingMultiSigCreations {
        let v0 = borrow_global<PendingMultiSigCreations>(@msafe);
        assert!(0x1::table::contains<address, MomentumSafeCreation>(&v0.creations, arg0), 15);
        let v1 = 0x1::table::borrow<address, MomentumSafeCreation>(&v0.creations, arg0);
        (v1.owners, v1.public_keys, v1.nonce, v1.threshold)
    }
    
    fun get_public_keys(arg0: &vector<address>) : vector<vector<u8>> {
        let v0 = 0x1::vector::empty<vector<u8>>();
        let v1 = 0;
        while (v1 < 0x1::vector::length<address>(arg0)) {
            0x1::vector::push_back<vector<u8>>(&mut v0, msafe::registry::get_public_key_verified(*0x1::vector::borrow<address>(arg0, v1)));
            v1 = v1 + 1;
        };
        v0
    }
    
    fun get_public_keys_and_check(arg0: &vector<address>, arg1: u64, arg2: u8) : vector<vector<u8>> {
        let v0 = 0x1::vector::length<address>(arg0);
        assert!(v0 > 1, 2);
        assert!(v0 <= arg1, 14);
        assert!((arg2 as u64) <= v0, 3);
        assert!(arg2 > 0, 21);
        let v1 = get_public_keys(arg0);
        assert!(msafe::utils::vector_dup_exist<vector<u8>>(&v1) == false, 17);
        v1
    }
    
    fun init_module(arg0: &signer) {
        assert!(msafe::utils::next_valid_nonce_public_key(0, 0x1::signer::address_of(arg0)) == 0, 19);
        if (!exists<PendingMultiSigCreations>(0x1::signer::address_of(arg0))) {
            let v0 = PendingMultiSigCreations{
                nonces    : 0x1::table::new<address, u64>(), 
                creations : 0x1::table::new<address, MomentumSafeCreation>(),
            };
            move_to<PendingMultiSigCreations>(arg0, v0);
            let v1 = MultiSigCreationEvent{events: 0x1::account::new_event_handle<MomentumSafeCreation>(arg0)};
            move_to<MultiSigCreationEvent>(arg0, v1);
        };
    }
    
    public entry fun init_wallet_creation(arg0: &signer, arg1: vector<address>, arg2: u8, arg3: u64, arg4: vector<u8>, arg5: vector<u8>) acquires MultiSigCreationEvent, PendingMultiSigCreations {
        init_wallet_creation_internal(arg0, arg1, arg2, arg3, arg4, arg5, @msafe);
    }
    
    public(friend) fun init_wallet_creation_internal(arg0: &signer, arg1: vector<address>, arg2: u8, arg3: u64, arg4: vector<u8>, arg5: vector<u8>, arg6: address) acquires MultiSigCreationEvent, PendingMultiSigCreations {
        let v0 = get_public_keys_and_check(&arg1, 31, arg2);
        let (v1, v2) = derive_new_multisig_auth_key(borrow_global_mut<PendingMultiSigCreations>(@msafe), *0x1::vector::borrow<address>(&arg1, 0), v0, arg2, arg6);
        validate_register_payload(arg4, v1, arg6, arg3);
        if (!0x1::account::exists_at(v1)) {
            0x1::aptos_account::create_account(v1);
        };
        assert!(0x1::account::get_sequence_number(v1) == 0, 16);
        0x1::coin::transfer<0x1::aptos_coin::AptosCoin>(arg0, v1, arg3);
        let v3 = CreateWalletTxn{
            payload    : arg4, 
            signatures : 0x1::simple_map::create<vector<u8>, vector<u8>>(),
        };
        let v4 = MomentumSafeCreation{
            owners      : arg1, 
            public_keys : v0, 
            nonce       : v2, 
            threshold   : arg2, 
            txn         : v3,
        };
        store_creation(v4, v1, 0, arg5);
    }
    
    public entry fun init_wallet_import(arg0: &signer, arg1: address, arg2: vector<address>, arg3: u8, arg4: u64, arg5: vector<u8>, arg6: u8, arg7: vector<u8>) acquires MultiSigCreationEvent, PendingMultiSigCreations {
        init_wallet_import_internal(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, @msafe);
    }
    
    public(friend) fun init_wallet_import_internal(arg0: &signer, arg1: address, arg2: vector<address>, arg3: u8, arg4: u64, arg5: vector<u8>, arg6: u8, arg7: vector<u8>, arg8: address) acquires MultiSigCreationEvent, PendingMultiSigCreations {
        let v0 = get_public_keys_and_check(&arg2, 32, arg3);
        if (!0x1::account::exists_at(arg1)) {
            0x1::aptos_account::create_account(arg1);
        };
        assert!(msafe::utils::multisig_public_keys_to_auth_key(v0, arg3) == 0x1::account::get_authentication_key(arg1), 20);
        validate_register_payload(arg5, arg1, arg8, arg4);
        assert!(0x1::vector::length<vector<u8>>(&v0) <= 32, 14);
        0x1::coin::transfer<0x1::aptos_coin::AptosCoin>(arg0, arg1, arg4);
        let v1 = CreateWalletTxn{
            payload    : arg5, 
            signatures : 0x1::simple_map::create<vector<u8>, vector<u8>>(),
        };
        let v2 = MomentumSafeCreation{
            owners      : arg2, 
            public_keys : v0, 
            nonce       : 18446744073709551615, 
            threshold   : arg3, 
            txn         : v1,
        };
        store_creation(v2, arg1, arg6, arg7);
    }
    
    public(friend) fun remove_wallet_creation(arg0: address) : (address, MomentumSafeCreation) acquires PendingMultiSigCreations {
        (arg0, 0x1::table::remove<address, MomentumSafeCreation>(&mut borrow_global_mut<PendingMultiSigCreations>(@msafe).creations, arg0))
    }
    
    fun store_creation(arg0: MomentumSafeCreation, arg1: address, arg2: u8, arg3: vector<u8>) acquires MultiSigCreationEvent, PendingMultiSigCreations {
        add_signature(&mut arg0, arg2, arg3);
        let v0 = arg0.owners;
        0x1::table::add<address, MomentumSafeCreation>(&mut borrow_global_mut<PendingMultiSigCreations>(@msafe).creations, arg1, arg0);
        add_to_registry(&v0, arg1);
        0x1::event::emit_event<MomentumSafeCreation>(&mut borrow_global_mut<MultiSigCreationEvent>(@msafe).events, arg0);
    }
    
    public entry fun submit_signature(arg0: address, arg1: u8, arg2: vector<u8>) acquires MultiSigCreationEvent, PendingMultiSigCreations {
        let v0 = 0x1::table::borrow_mut<address, MomentumSafeCreation>(&mut borrow_global_mut<PendingMultiSigCreations>(@msafe).creations, arg0);
        add_signature(v0, arg1, arg2);
        0x1::event::emit_event<MomentumSafeCreation>(&mut borrow_global_mut<MultiSigCreationEvent>(@msafe).events, *v0);
    }
    
    fun validate_register_payload(arg0: vector<u8>, arg1: address, arg2: address, arg3: u64) {
        let v0 = msafe::transaction::decode_transaction(arg0);
        let v1 = msafe::transaction::get_sender(&v0);
        assert!(v1 == arg1, 5);
        assert!(msafe::transaction::get_chain_id(&v0) == 0x1::chain_id::get(), 18);
        let v2 = if (0x1::account::exists_at(v1)) {
            0x1::account::get_sequence_number(v1)
        } else {
            0
        };
        assert!(msafe::transaction::get_sequence_number(&v0) == v2, 6);
        assert!(msafe::transaction::get_expiration_timestamp_secs(&v0) > msafe::utils::now_seconds(), 7);
        let (v3, v4) = msafe::transaction::get_module_name(&v0);
        assert!(v3 == arg2, 9);
        assert!(v4 == b"momentum_safe", 9);
        assert!(msafe::transaction::get_function_name(&v0) == b"register", 10);
        let v5 = msafe::transaction::get_max_gas_amount(&v0);
        let v6 = msafe::transaction::get_gas_unit_price(&v0);
        assert!(v5 >= 2000, 11);
        assert!(v6 >= 1, 12);
        assert!(v5 * v6 <= arg3, 13);
    }
    
    // decompiled from Move bytecode v6
}


module 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::momentum_safe {
    struct Info has copy, drop, store {
        owners: vector<address>,
        public_keys: vector<vector<u8>>,
        nonce: u64,
        threshold: u8,
        metadata: vector<u8>,
    }
    
    struct Migration has key {
        metadatas: 0x1::table::Table<address, 0x1::simple_map::SimpleMap<u64, 0x1::simple_map::SimpleMap<0x1::string::String, vector<u8>>>>,
        event: 0x1::event::EventHandle<MigrationEvent>,
    }
    
    struct MigrationEvent has drop, store {
        msafe_address: address,
        info: Info,
        metadatas: 0x1::simple_map::SimpleMap<0x1::string::String, vector<u8>>,
    }
    
    struct Momentum has key {
        info: Info,
        txn_book: TxnBook,
    }
    
    struct MomentumSafeEvent has key {
        register_events: 0x1::event::EventHandle<Info>,
        transaction_events: 0x1::event::EventHandle<Transaction>,
    }
    
    struct Transaction has copy, drop, store {
        payload: vector<u8>,
        metadata: vector<u8>,
        signatures: 0x1::simple_map::SimpleMap<vector<u8>, vector<u8>>,
    }
    
    struct TxnBook has store {
        min_sequence_number: u64,
        max_sequence_number: u64,
        tx_hashes: 0x1::table_with_length::TableWithLength<u64, vector<vector<u8>>>,
        pendings: 0x1::table_with_length::TableWithLength<vector<u8>, Transaction>,
    }
    
    fun mark_migrated(arg0: &mut Momentum) {
        arg0.txn_book.min_sequence_number = 18446744073709551615;
    }
    
    fun verify_signature(arg0: vector<u8>, arg1: vector<u8>, arg2: vector<u8>) {
        assert!(0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::utils::verify_signature(arg0, arg1, arg2), 1);
    }
    
    fun add_metadata(arg0: address, arg1: u64, arg2: vector<0x1::string::String>, arg3: vector<vector<u8>>) acquires Migration {
        let v0 = borrow_global_mut<Migration>(@0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e);
        if (!0x1::table::contains<address, 0x1::simple_map::SimpleMap<u64, 0x1::simple_map::SimpleMap<0x1::string::String, vector<u8>>>>(&v0.metadatas, arg0)) {
            0x1::table::add<address, 0x1::simple_map::SimpleMap<u64, 0x1::simple_map::SimpleMap<0x1::string::String, vector<u8>>>>(&mut v0.metadatas, arg0, 0x1::simple_map::new<u64, 0x1::simple_map::SimpleMap<0x1::string::String, vector<u8>>>());
        };
        let (_, _) = 0x1::simple_map::upsert<u64, 0x1::simple_map::SimpleMap<0x1::string::String, vector<u8>>>(0x1::table::borrow_mut<address, 0x1::simple_map::SimpleMap<u64, 0x1::simple_map::SimpleMap<0x1::string::String, vector<u8>>>>(&mut v0.metadatas, arg0), arg1, 0x1::simple_map::new_from<0x1::string::String, vector<u8>>(arg2, arg3));
    }
    
    fun add_signature(arg0: &mut Transaction, arg1: vector<u8>, arg2: vector<u8>) {
        verify_signature(arg2, arg1, arg0.payload);
        0x1::simple_map::add<vector<u8>, vector<u8>>(&mut arg0.signatures, arg1, arg2);
    }
    
    fun add_to_registry(arg0: vector<address>, arg1: address) {
        0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::registry::register_msafe(&arg0, arg1, false);
    }
    
    fun add_to_txn_book(arg0: &mut TxnBook, arg1: u64, arg2: Transaction) {
        if (arg1 > arg0.max_sequence_number) {
            arg0.max_sequence_number = arg0.max_sequence_number + 1;
        };
        assert!(arg1 <= arg0.max_sequence_number, 2);
        let v0 = 0x1::hash::sha3_256(arg2.payload);
        0x1::table_with_length::add<vector<u8>, Transaction>(&mut arg0.pendings, v0, arg2);
        if (!0x1::table_with_length::contains<u64, vector<vector<u8>>>(&arg0.tx_hashes, arg1)) {
            0x1::table_with_length::add<u64, vector<vector<u8>>>(&mut arg0.tx_hashes, arg1, 0x1::vector::empty<vector<u8>>());
        };
        0x1::vector::push_back<vector<u8>>(0x1::table_with_length::borrow_mut<u64, vector<vector<u8>>>(&mut arg0.tx_hashes, arg1), v0);
    }
    
    fun create_momentum(arg0: &signer, arg1: vector<address>, arg2: vector<vector<u8>>, arg3: u64, arg4: u8, arg5: vector<u8>) {
        let v0 = Info{
            owners      : arg1, 
            public_keys : arg2, 
            nonce       : arg3, 
            threshold   : arg4, 
            metadata    : arg5,
        };
        let v1 = 0x1::account::get_sequence_number(0x1::signer::address_of(arg0));
        let v2 = TxnBook{
            min_sequence_number : v1, 
            max_sequence_number : v1, 
            tx_hashes           : 0x1::table_with_length::new<u64, vector<vector<u8>>>(), 
            pendings            : 0x1::table_with_length::new<vector<u8>, Transaction>(),
        };
        let v3 = Momentum{
            info     : v0, 
            txn_book : v2,
        };
        move_to<Momentum>(arg0, v3);
        let v4 = 0x1::account::new_event_handle<Info>(arg0);
        0x1::event::emit_event<Info>(&mut v4, v0);
        let v5 = MomentumSafeEvent{
            register_events    : v4, 
            transaction_events : 0x1::account::new_event_handle<Transaction>(arg0),
        };
        move_to<MomentumSafeEvent>(arg0, v5);
    }
    
    public entry fun do_nothing() {
    }
    
    public entry fun enable_migration(arg0: &signer) {
        assert!(0x1::signer::address_of(arg0) == @0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e, 7);
        let v0 = Migration{
            metadatas : 0x1::table::new<address, 0x1::simple_map::SimpleMap<u64, 0x1::simple_map::SimpleMap<0x1::string::String, vector<u8>>>>(), 
            event     : 0x1::account::new_event_handle<MigrationEvent>(arg0),
        };
        move_to<Migration>(arg0, v0);
    }
    
    fun get_metadata(arg0: address) : (vector<0x1::string::String>, vector<vector<u8>>) acquires Migration {
        let v0 = 0x1::account::get_sequence_number(arg0);
        0x1::simple_map::to_vec_pair<0x1::string::String, vector<u8>>(*0x1::simple_map::borrow<u64, 0x1::simple_map::SimpleMap<0x1::string::String, vector<u8>>>(0x1::table::borrow<address, 0x1::simple_map::SimpleMap<u64, 0x1::simple_map::SimpleMap<0x1::string::String, vector<u8>>>>(&borrow_global<Migration>(@0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e).metadatas, arg0), &v0))
    }
    
    public entry fun init_migration(arg0: address, arg1: u8, arg2: u64, arg3: vector<u8>, arg4: vector<0x1::string::String>, arg5: vector<vector<u8>>) acquires Migration, Momentum, MomentumSafeEvent {
        let v0 = 0x1::account::get_sequence_number(arg0);
        assert!(v0 <= arg2, 2);
        let v1 = borrow_global_mut<Momentum>(arg0);
        add_metadata(arg0, arg2, arg4, arg5);
        init_transaction_internal(arg0, arg1, 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::migration::build_proof_challenge(arg0, arg2, v1.info.owners, v1.info.threshold), arg3, arg2, v0);
    }
    
    public entry fun init_transaction(arg0: address, arg1: u8, arg2: vector<u8>, arg3: vector<u8>) acquires Momentum, MomentumSafeEvent {
        let (v0, v1) = validate_txn_payload(arg0, arg2);
        init_transaction_internal(arg0, arg1, arg2, arg3, v0, v1);
    }
    
    fun init_transaction_internal(arg0: address, arg1: u8, arg2: vector<u8>, arg3: vector<u8>, arg4: u64, arg5: u64) acquires Momentum, MomentumSafeEvent {
        let v0 = borrow_global_mut<Momentum>(arg0);
        assert!(!is_migrated(v0), 6);
        let v1 = Transaction{
            payload    : arg2, 
            metadata   : 0x1::vector::empty<u8>(), 
            signatures : 0x1::simple_map::create<vector<u8>, vector<u8>>(),
        };
        add_signature(&mut v1, *0x1::vector::borrow<vector<u8>>(&v0.info.public_keys, arg1 as u64), arg3);
        add_to_txn_book(&mut v0.txn_book, arg4, v1);
        try_prune_pre_txs(&mut v0.txn_book, arg5 - 1);
        0x1::event::emit_event<Transaction>(&mut borrow_global_mut<MomentumSafeEvent>(arg0).transaction_events, v1);
    }
    
    fun is_migrated(arg0: &Momentum) : bool {
        arg0.txn_book.min_sequence_number == 18446744073709551615
    }
    
    public entry fun migrate(arg0: address, arg1: vector<u8>, arg2: vector<u8>) acquires Migration, Momentum {
        let v0 = borrow_global_mut<Momentum>(arg0);
        mark_migrated(v0);
        0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::registry::mark_migrated(&v0.info.owners, arg0);
        let (v1, v2) = get_metadata(arg0);
        0x1::multisig_account::create_with_existing_account_and_revoke_auth_key(arg0, v0.info.owners, v0.info.threshold as u64, 1, arg1, arg2, v1, v2);
        let v3 = MigrationEvent{
            msafe_address : arg0, 
            info          : v0.info, 
            metadatas     : 0x1::simple_map::new_from<0x1::string::String, vector<u8>>(v1, v2),
        };
        0x1::event::emit_event<MigrationEvent>(&mut borrow_global_mut<Migration>(@0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e).event, v3);
    }
    
    public fun msafe_status(arg0: address) : u8 acquires Momentum {
        let v0 = borrow_global<Momentum>(arg0);
        if (is_migrated(v0)) {
            return 2
        };
        let v1 = 0x1::account::get_sequence_number(arg0);
        while (v1 <= v0.txn_book.max_sequence_number) {
            let v2 = 0x1::table_with_length::borrow<u64, vector<vector<u8>>>(&v0.txn_book.tx_hashes, v1);
            let v3 = 0;
            while (v3 < 0x1::vector::length<vector<u8>>(v2)) {
                if (0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::migration::is_proof_challenge(0x1::table_with_length::borrow<vector<u8>, Transaction>(&v0.txn_book.pendings, *0x1::vector::borrow<vector<u8>>(v2, v3)).payload)) {
                    return 1
                };
                v3 = v3 + 1;
            };
            v1 = v1 + 1;
        };
        0
    }
    
    public fun msafe_vec_status(arg0: vector<address>) : vector<u8> acquires Momentum {
        let v0 = 0x1::vector::empty<u8>();
        let v1 = 0;
        while (v1 < 0x1::vector::length<address>(&arg0)) {
            let v2 = msafe_status(*0x1::vector::borrow<address>(&arg0, v1));
            0x1::vector::push_back<u8>(&mut v0, v2);
            v1 = v1 + 1;
        };
        v0
    }
    
    fun prune_txs_at(arg0: &mut TxnBook, arg1: u64, arg2: u8) : (u8, bool) {
        if (0x1::table_with_length::contains<u64, vector<vector<u8>>>(&arg0.tx_hashes, arg1)) {
            let v0 = 0x1::table_with_length::remove<u64, vector<vector<u8>>>(&mut arg0.tx_hashes, arg1);
            while (!0x1::vector::is_empty<vector<u8>>(&v0) && arg2 > 0) {
                arg2 = arg2 - 1;
                0x1::table_with_length::remove<vector<u8>, Transaction>(&mut arg0.pendings, 0x1::vector::pop_back<vector<u8>>(&mut v0));
            };
            if (!0x1::vector::is_empty<vector<u8>>(&v0)) {
                0x1::table_with_length::add<u64, vector<vector<u8>>>(&mut arg0.tx_hashes, arg1, v0);
                return (arg2, true)
            };
        };
        (arg2, false)
    }
    
    public entry fun register(arg0: &signer, arg1: vector<u8>) {
        let v0 = 0x1::signer::address_of(arg0);
        if (!0x1::account::exists_at(v0)) {
            return
        };
        let (v1, v2, v3, v4) = 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::creator::get_creation(v0);
        create_momentum(arg0, v1, v2, v3, v4, arg1);
        let (_, _) = 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::creator::remove_wallet_creation(v0);
        add_to_registry(v1, v0);
    }
    
    public entry fun submit_signature(arg0: address, arg1: u8, arg2: vector<u8>, arg3: vector<u8>) acquires Momentum, MomentumSafeEvent {
        let v0 = borrow_global_mut<Momentum>(arg0);
        let v1 = 0x1::table_with_length::borrow_mut<vector<u8>, Transaction>(&mut v0.txn_book.pendings, arg2);
        add_signature(v1, *0x1::vector::borrow<vector<u8>>(&v0.info.public_keys, arg1 as u64), arg3);
        0x1::event::emit_event<Transaction>(&mut borrow_global_mut<MomentumSafeEvent>(arg0).transaction_events, *v1);
    }
    
    fun try_prune_pre_txs(arg0: &mut TxnBook, arg1: u64) {
        let v0 = arg0.min_sequence_number;
        let v1 = 128;
        while (v0 <= arg1 && v1 > 0) {
            let (v2, v3) = prune_txs_at(arg0, v0, v1);
            v1 = v2;
            if (v3) {
                break
            };
            v0 = v0 + 1;
        };
        arg0.min_sequence_number = v0;
    }
    
    fun validate_txn_payload(arg0: address, arg1: vector<u8>) : (u64, u64) {
        let v0 = 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::transaction::decode_transaction(arg1);
        assert!(0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::transaction::get_sender(&v0) == arg0, 3);
        assert!(0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::transaction::get_chain_id(&v0) == 0x1::chain_id::get(), 5);
        let v1 = 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::transaction::get_sequence_number(&v0);
        let v2 = 0x1::account::get_sequence_number(arg0);
        assert!(v2 <= v1, 2);
        assert!(0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::transaction::get_expiration_timestamp_secs(&v0) > 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::utils::now_seconds(), 4);
        (v1, v2)
    }
    
    // decompiled from Move bytecode v6
}


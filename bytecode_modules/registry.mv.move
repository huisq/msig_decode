module 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::registry {
    struct OwnerMomentumSafes has key {
        public_key: vector<u8>,
        pendings: 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::TableMap<address, bool>,
        msafes: 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::TableMap<address, bool>,
    }
    
    struct OwnerMomentumSafesChangeEvent has drop, store {
        public_key: vector<u8>,
        msafe: address,
        op_type: u8,
        pendings_length: u64,
        msafes_length: u64,
    }
    
    struct RegisterEvent has key {
        events: 0x1::event::EventHandle<OwnerMomentumSafesChangeEvent>,
    }
    
    fun add_momentum_safe(arg0: address, arg1: address) acquires OwnerMomentumSafes, RegisterEvent {
        assert!(exists<OwnerMomentumSafes>(arg0), 2);
        let v0 = &mut borrow_global_mut<OwnerMomentumSafes>(arg0).msafes;
        if (!contain_address(v0, arg1)) {
            0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::add<address, bool>(v0, arg1, true);
            emit_register_event(arg0, arg1, 3);
        };
    }
    
    fun add_pending_msafe(arg0: address, arg1: address) acquires OwnerMomentumSafes, RegisterEvent {
        assert!(exists<OwnerMomentumSafes>(arg0), 2);
        let v0 = borrow_global_mut<OwnerMomentumSafes>(arg0);
        assert!(!0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::contains_key<address, bool>(&v0.msafes, &arg1), 5);
        let v1 = &mut v0.pendings;
        if (!contain_address(v1, arg1)) {
            0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::add<address, bool>(v1, arg1, true);
            emit_register_event(arg0, arg1, 2);
        };
    }
    
    fun confirm_pending_msafe(arg0: address, arg1: address) acquires OwnerMomentumSafes, RegisterEvent {
        assert!(exists<OwnerMomentumSafes>(arg0), 2);
        let v0 = &mut borrow_global_mut<OwnerMomentumSafes>(arg0).pendings;
        assert!(0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::contains_key<address, bool>(v0, &arg1), 3);
        let (_, _) = 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::remove<address, bool>(v0, &arg1);
        add_momentum_safe(arg0, arg1);
    }
    
    fun contain_address(arg0: &0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::TableMap<address, bool>, arg1: address) : bool {
        0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::contains_key<address, bool>(arg0, &arg1)
    }
    
    fun emit_register_event(arg0: address, arg1: address, arg2: u8) acquires OwnerMomentumSafes, RegisterEvent {
        let v0 = borrow_global<OwnerMomentumSafes>(arg0);
        let v1 = OwnerMomentumSafesChangeEvent{
            public_key      : v0.public_key, 
            msafe           : arg1, 
            op_type         : arg2, 
            pendings_length : 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::length<address, bool>(&v0.pendings), 
            msafes_length   : 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::length<address, bool>(&v0.msafes),
        };
        0x1::event::emit_event<OwnerMomentumSafesChangeEvent>(&mut borrow_global_mut<RegisterEvent>(arg0).events, v1);
    }
    
    fun find_address(arg0: &vector<address>, arg1: address) : (bool, u64) {
        let v0 = 0;
        while (v0 < 0x1::vector::length<address>(arg0)) {
            if (arg1 == *0x1::vector::borrow<address>(arg0, v0)) {
                return (true, v0)
            };
            v0 = v0 + 1;
        };
        (false, 0)
    }
    
    public fun get_owned_msafes(arg0: address) : (0x1::simple_map::SimpleMap<address, bool>, 0x1::simple_map::SimpleMap<address, bool>) acquires OwnerMomentumSafes {
        let v0 = borrow_global<OwnerMomentumSafes>(arg0);
        (0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::utils::table_map_to_simple_map<address, bool>(&v0.pendings), 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::utils::table_map_to_simple_map<address, bool>(&v0.msafes))
    }
    
    public fun get_public_key_verified(arg0: address) : vector<u8> acquires OwnerMomentumSafes {
        assert!(is_registered(arg0), 2);
        let v0 = borrow_global<OwnerMomentumSafes>(arg0).public_key;
        assert!(verify_public_key(arg0, v0), 4);
        v0
    }
    
    fun is_registered(arg0: address) : bool {
        exists<OwnerMomentumSafes>(arg0)
    }
    
    public(friend) fun mark_migrated(arg0: &vector<address>, arg1: address) acquires OwnerMomentumSafes, RegisterEvent {
        let v0 = 0;
        while (v0 < 0x1::vector::length<address>(arg0)) {
            migrate_momentum_safe(*0x1::vector::borrow<address>(arg0, v0), arg1);
            v0 = v0 + 1;
        };
    }
    
    fun migrate_momentum_safe(arg0: address, arg1: address) acquires OwnerMomentumSafes, RegisterEvent {
        assert!(exists<OwnerMomentumSafes>(arg0), 2);
        *0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::borrow_mut<address, bool>(&mut borrow_global_mut<OwnerMomentumSafes>(arg0).msafes, &arg1) = false;
        emit_register_event(arg0, arg1, 4);
    }
    
    public entry fun register(arg0: &signer, arg1: vector<u8>) {
        let v0 = 0x1::signer::address_of(arg0);
        assert!(!is_registered(v0), 1);
        assert!(verify_public_key(v0, arg1), 4);
        let v1 = OwnerMomentumSafes{
            public_key : arg1, 
            pendings   : 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::create<address, bool>(), 
            msafes     : 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map::create<address, bool>(),
        };
        move_to<OwnerMomentumSafes>(arg0, v1);
        let v2 = RegisterEvent{events: 0x1::account::new_event_handle<OwnerMomentumSafesChangeEvent>(arg0)};
        let v3 = OwnerMomentumSafesChangeEvent{
            public_key      : arg1, 
            msafe           : @0x0, 
            op_type         : 1, 
            pendings_length : 0, 
            msafes_length   : 0,
        };
        0x1::event::emit_event<OwnerMomentumSafesChangeEvent>(&mut v2.events, v3);
        move_to<RegisterEvent>(arg0, v2);
    }
    
    public(friend) fun register_msafe(arg0: &vector<address>, arg1: address, arg2: bool) acquires OwnerMomentumSafes, RegisterEvent {
        let v0 = 0;
        while (v0 < 0x1::vector::length<address>(arg0)) {
            let v1 = *0x1::vector::borrow<address>(arg0, v0);
            if (arg2) {
                add_pending_msafe(v1, arg1);
            } else {
                confirm_pending_msafe(v1, arg1);
            };
            v0 = v0 + 1;
        };
    }
    
    fun verify_public_key(arg0: address, arg1: vector<u8>) : bool {
        0x1::account::get_authentication_key(arg0) == 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::utils::derive_auth_key(arg1)
    }
    
    // decompiled from Move bytecode v6
}


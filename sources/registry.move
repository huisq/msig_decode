/// Registry serves as the data query for each address tracking their owned
/// momentum safes.
///
/// Owned momentum safe wallet address is stored under each account resource
/// as `OwnerMomentumSafes` which tracks three fields for each account:
///     1. Public key: public key associated with the wallet account.
///     2. Pendings: momentum safe wallets that is in pending creation.
///     3. Created MSafes: momentum safe that has already been created.
///
/// The module is used as follows:
///     1. When the user first time interact with momentum safe, they need to
///         register to registry module to have the intial data.
///     2. When a new momentum safe creation request is initialized via
///         `creator::init_wallet_creation`, the wallet address will be
///         added to each owner's `OwnerMomentumSafes.pendings`
///     3. When the momentum safe is already created and finished registration
///         in `momentum_safe` via `momentum_safe::register`, the momentum
///         safe address will be removed from `OwnerMomentumSafes.pendings`
///         to `OwnerMomentumSafes.msafes`.
///
module msafe::registry {

    use std::signer;
    use std::vector;

    use aptos_framework::account;
    use aptos_std::event::{Self, EventHandle};

    use msafe::utils;
    use msafe::table_map::{Self, TableMap};

    #[test_only]
    use aptos_framework::aptos_account;
    use aptos_std::simple_map::SimpleMap;

    // When user initiates a momentum_safe in creator module, the pending creation
    // per owner is written in `registry::OwnerMomentumSafes` so that the owner is
    // able to query for their pending momentum_safe creations.
    friend msafe::creator;

    // Upon successfully registered momentum_safe (in momentum_safe::register),
    // module momentum_safe will move the entry from pendings to msafes in
    // OwnerMomentumSafes using friend function `register_multi_sigs`.
    friend msafe::momentum_safe;

    // Error codes

    /// Error code for duplicate address registration.
    const EADDRESS_ALREADY_REGISTERED: u64 = 1;

    /// Error code for the user request updates on non-initialized data
    /// which is not registered previously.
    const EADDRESS_NOT_REGISTRERED: u64 = 2;

    /// Error code for user unregistering a momentum safe which is not
    /// registered previously.
    const EMSAFE_NOT_REGISTERED: u64 = 3;

    /// Error code for user has rotated their public key. In the current
    /// implementation, since the key rotation interface in Aptos account.move
    /// is not finalized, client side key rotation is not supported.
    ///
    /// The key rotation feature (multi-sig wallet permission change & multi-sig
    /// wallet key rotation according to single wallet key rotation) will be
    /// supported shortly.
    const EPUBLIC_KEY_ROTATED: u64 = 4;

    /// Error code for MSAFE already exist
    const EMSAFE_ALREADY_EXIST: u64 = 5;

    const OP_MSAFE_INIT: u8 = 1;
    const OP_MSAFE_PENDING: u8 = 2;
    const OP_MSAFE_CONFIRM: u8 = 3;
    const OP_MSAFE_MIGRATE: u8 = 4;

    /// Keep track of the momentum safe addresses owned by an owner address.
    /// The data is published under each address's resource.
    ///
    /// The following data is stored on chain under the account resource:
    ///     1. Public Key: The public key when user registers his account into
    ///             Momentum Safe. The public key is used to check whether
    ///             user has conducted a key rotation.
    ///     2. Pendings: Momentum Safe wallet addresses that are in pending
    ///             creation status. The address will be cleared if the wallet
    ///             is successfully registered in momentum_safe.
    ///     3. msafes: Momentum Safe wallet addresses that has already been
    ///             registered.
    struct OwnerMomentumSafes has key {
        public_key: vector<u8>,
        // we use TableMap, beacuse anyone can add a new msafe into others pending list.
        // if we use vector<address> here, it may have performance issues.
        // the `bool` just used to hold the Value position of table, it is always true.
        pendings: TableMap<address, bool>,
        msafes: TableMap<address, bool>,
    }

    struct OwnerMomentumSafesChangeEvent has store, drop {
        public_key: vector<u8>,
        msafe: address,
        op_type: u8,
        pendings_length: u64,
        msafes_length: u64,
    }

    /// Event handler for each address.
    /// Emit the event with structure `OwnerMomentumSafe` when a registration
    /// or unregistration happens.
    struct RegisterEvent has key {
        events: EventHandle<OwnerMomentumSafesChangeEvent>
    }

    /// Publish the OwnerMomentumSafe under the user's account resource.
    /// The the function shall be called only once when user is first interacting
    /// with momentum safe modules. The user public key is required for the
    /// registration, used for tracking user's key rotation.
    ///
    /// # Parameters
    /// * `s`: The signer object from the single signed wallet.
    /// * `public_key`: User's public key.
    ///
    /// # Emits
    /// * `RegisterEvent`: `OwnerMomentumSafes` struct that holds addresses owned by
    ///         the signer.
    ///
    /// # Aborts
    /// * `EADDRESS_ALREADY_REGISTERED`: User has registered before;
    /// * `EPUBLIC_KEY_ROTATED`: The input public key does not match the auth
    ///         key in `account.move`.
    public entry fun register(
        s: &signer,
        public_key: vector<u8>,
    ) {
        let signer_address = signer::address_of(s);

        // Check whether user has registered before.
        assert!(!is_registered(signer_address), EADDRESS_ALREADY_REGISTERED);

        // Check whether the input public key matches user's authentication key.
        assert!(verify_public_key(signer_address, public_key), EPUBLIC_KEY_ROTATED);

        // Construct OwnerMomentumSafes and write to account resource
        let momentum_safes = OwnerMomentumSafes {
            public_key,
            pendings: table_map::create(),
            msafes: table_map::create()
        };
        move_to(s, momentum_safes);

        // Write event handler to inform user's owner msafe changes.
        let register_event = RegisterEvent {
            events: account::new_event_handle<OwnerMomentumSafesChangeEvent>(s)
        };
        // The explicit move operation here avoids an unnecessary copy of the complicated
        // data structure OwnerMomentumSafe.
        event::emit_event(&mut register_event.events, OwnerMomentumSafesChangeEvent {
            public_key,
            msafe: @0x0,
            op_type: OP_MSAFE_INIT,
            pendings_length: 0,
            msafes_length: 0,
        });
        move_to(s, register_event);
    }


    /// Verifies the input public key versus the authentication key stored in
    /// `account.move`.
    ///
    /// For a valid verification, the authentication key in `account.move` should
    /// equal to `sha3-256(public_key)` according to Aptos account model.
    ///
    /// # Parameters
    /// * `account`: address of the target account to verify.
    /// * `public_key`: user input public key to be verified.
    ///
    /// # Returns
    /// * `bool`: whether the verification passes.
    fun verify_public_key(
        account: address,
        public_key: vector<u8>,
    ): bool {
        let real_auth_key = account::get_authentication_key(account);
        let derived_auth_key = utils::derive_auth_key(public_key);
        real_auth_key == derived_auth_key
    }

    /// Return the public key that has previously been verified and stored in
    /// account resource. If the account's key has been rotated, they will lose
    /// access to the momentum safes.
    ///
    /// # Parameters
    /// * `account`: address of the query account.
    ///
    /// # Returns
    /// * `vector<u8>`: public key previously stored in account resource
    ///
    /// # Aborts
    /// * `EADDRESS_NOT_REGISTRERED`: The account hasn't been registered before.
    /// * `EPUBLIC_KEY_ROTATED`: The account's public key is different from what
    ///         was previously stored during registration.
    public fun get_public_key_verified(
        account: address,
    ): vector<u8> acquires OwnerMomentumSafes {
        assert!(is_registered(account), EADDRESS_NOT_REGISTRERED);
        let public_key = borrow_global<OwnerMomentumSafes>(account).public_key;
        assert!(verify_public_key(account, public_key), EPUBLIC_KEY_ROTATED);
        public_key
    }

    /// Register the multi-sig wallet to the owners. Only called by friend modules
    /// including creator and momentum_safe.
    ///
    /// If the caller is `creator::init_wallet_creation_internal`, add the momentum
    /// safe address to `pending` under each addresses' `OwnerMomentumSafes`
    /// structure.
    ///
    /// Else if the caller is `momentum_safe::register`, remove the address from
    /// each addresses `OwnerMomentumSafes.pendings` and add to `OwnerMomentumSafes.
    /// msafes`.
    ///
    /// # Parameters
    /// * `owners`: list of addresses of the multi-sig owners.
    /// * `msafe_addr`: the address of the momentum safe multi-sig wallet.
    /// * `pending`: Whether the request is from pending creation or account
    ///         that have been previously registered.
    ///
    /// # Aborts
    /// * `EADDRESS_NOT_REGISTRERED`: address not registered
    /// * `EMULTI_SIG_NOT_REGISTERED`: Calling with pending = false, and multi-sig
    ///         is not registered previously.
    ///
    /// # Emits
    /// * `RegisterEvent` if the msafe_addr is added in owner resource.
    public(friend) fun register_msafe(
        owners: &vector<address>,
        msafe_addr: address,
        pending: bool
    ) acquires OwnerMomentumSafes, RegisterEvent {
        let i = 0;
        let len = vector::length<address>(owners);
        while (i < len) {
            let owner = *vector::borrow(owners, i);
            if (pending) {
                add_pending_msafe(owner, msafe_addr)
            } else {
                confirm_pending_msafe(owner, msafe_addr)
            };
            i = i + 1
        }
    }

    /// Emit a register event associated with user's address that has all the information
    /// in owner owned addresses. The emit function is called when there is a change for
    /// user owned momentum safe wallets.
    ///
    /// # Parameters
    /// * `owner`: owner address to emit the registration event.
    ///
    /// # Emits
    /// * `RegisterEvent`: `OwnerMomentumSafes` struct that holds addresses owned by the
    ///         owner.
    fun emit_register_event(
        owner: address, msafe: address, op_type: u8
    ) acquires OwnerMomentumSafes, RegisterEvent {
        let event_handle = borrow_global_mut<RegisterEvent>(owner);
        let owner_momentum_safes = borrow_global<OwnerMomentumSafes>(owner);
        event::emit_event(
            &mut event_handle.events,
            OwnerMomentumSafesChangeEvent {
                public_key: owner_momentum_safes.public_key,
                msafe,
                op_type,
                pendings_length: table_map::length(&owner_momentum_safes.pendings),
                msafes_length: table_map::length(&owner_momentum_safes.msafes),
            }
        )
    }


    /// Return whether the account address has previously been registered within
    /// the move module.
    ///
    /// # Parameters
    /// * `owner`: address
    ///
    /// # Returns
    /// * `bool`: whether the owner has been registered before.
    fun is_registered(
        owner: address,
    ): bool {
        exists<OwnerMomentumSafes>(owner)
    }

    /// Confirm momentum safe is successfully created, called from momentum_safe::register
    /// when momentum safe is registered. Remove the msafe address from owner's pending
    /// list, and add to the list of created msafes. Emit the `RegisterEvent` if owner's
    /// `OwnerMomentumSafes` has changes.
    ///
    /// # Parameters
    /// * `owner`: owner address.
    /// * `msafe`: msafe wallet address to be added.
    ///
    /// # Aborts
    /// * `EADDRESS_NOT_REGISTRERED`: Owner has not registered.
    ///
    /// # Emits
    /// * `RegisterEvent` if change in `OwnerMomentumSafe`.
    fun confirm_pending_msafe(
        owner: address,
        msafe: address,
    ) acquires OwnerMomentumSafes, RegisterEvent {
        assert!(exists<OwnerMomentumSafes>(owner), EADDRESS_NOT_REGISTRERED);
        let pendings = &mut borrow_global_mut<OwnerMomentumSafes>(owner).pendings;
        assert!(table_map::contains_key(pendings, &msafe), EMSAFE_NOT_REGISTERED);
        table_map::remove(pendings, &msafe);
        add_momentum_safe(owner, msafe);
    }

    /// Add msafe address to owner's momentum safe address list, which is
    /// `OwnerMomentumSafes.msafes`
    ///
    /// # Parameters
    /// * `owner`: owner address.
    /// * `msafe`: momentum safe address.
    ///
    /// # Aborts
    /// * `EADDRESS_NOT_REGISTRERED`: the owner address has not registered.
    ///
    /// # Emits
    /// * `RegisterEvent` if msafe is added in owner msafes.
    fun add_momentum_safe(
        owner: address,
        msafe: address,
    ) acquires OwnerMomentumSafes, RegisterEvent {
        // Get the OwnerMomentumSafes from the account resource
        assert!(exists<OwnerMomentumSafes>(owner), EADDRESS_NOT_REGISTRERED);
        let msafes = &mut borrow_global_mut<OwnerMomentumSafes>(owner).msafes;

        // If msafe is not previously registered, add it to account owned msafes.
        let exist = contain_address(msafes, msafe);
        if (!exist) {
            table_map::add(msafes, msafe, true);
            emit_register_event(owner, msafe, OP_MSAFE_CONFIRM);
        }
    }

    /// Add msafe address to owner's momentum safe address list, which is
    /// `OwnerMomentumSafes.msafes`
    ///
    /// # Parameters
    /// * `owner`: owner address.
    /// * `msafe`: momentum safe address.
    ///
    /// # Aborts
    /// * `EADDRESS_NOT_REGISTRERED`: the owner address has not registered.
    ///
    /// # Emits
    /// * `RegisterEvent` if the address is not already registered in pendings.
    fun add_pending_msafe(
        owner: address,
        msafe: address,
    ) acquires OwnerMomentumSafes, RegisterEvent {
        // Get the OwnerMomentumSafes from account resource
        assert!(exists<OwnerMomentumSafes>(owner), EADDRESS_NOT_REGISTRERED);
        let owner_msafe = borrow_global_mut<OwnerMomentumSafes>(owner);
        assert!(!table_map::contains_key(&owner_msafe.msafes, &msafe), EMSAFE_ALREADY_EXIST);
        let pendings = &mut owner_msafe.pendings;
        // If the msafe address is not registered in pendings, add to pendings
        // and emit the event.
        let exist = contain_address(pendings, msafe);
        if (!exist) {
            table_map::add(pendings, msafe, true);
            emit_register_event(owner, msafe, OP_MSAFE_PENDING);
        }
    }

    /// Check whether the target address exists in the address vector.
    ///
    /// # Parameters
    /// * `v`: address vector to be searched.
    /// * `target`: target address to be found.
    ///
    /// # Returns
    /// * `bool`: Whether the target address is found in address vector.
    fun contain_address(
        v: &TableMap<address, bool>,
        target: address,
    ): bool {
        table_map::contains_key(v, &target)
    }

    /// Find the address within the address vector.
    ///
    /// # Parameters
    /// * `v`: address vector to be searched.
    /// * `target`: target address to be found.
    ///
    /// # Returns
    /// * `bool`: Whether the target address is found in address vector.
    /// * `u64`: The index of the target address. If not found, return 0.
    fun find_address(
        v: &vector<address>,
        target: address,
    ): (bool, u64) {
        let i = 0;
        let len = vector::length(v);
        while (i < len) {
            if (target == *(vector::borrow(v, i))) {
                return (true, i)
            };
            i = i + 1;
        };
        (false, 0)
    }

    /// Mark the momentum safe as migrated.
    ///
    /// # Parameters
    /// * `owners`: vector of owner addresses.
    /// * `msafe_addr`: momentum safe address.
    public(friend) fun mark_migrated(
        owners: &vector<address>,
        msafe_addr: address,
    ) acquires OwnerMomentumSafes, RegisterEvent {
        let i = 0;
        let len = vector::length<address>(owners);
        while (i < len) {
            let owner = *vector::borrow(owners, i);
            migrate_momentum_safe(owner, msafe_addr);
            i = i + 1
        }
    }

    fun migrate_momentum_safe(
        owner: address,
        msafe: address,
    ) acquires OwnerMomentumSafes, RegisterEvent {
        // Get the OwnerMomentumSafes from the account resource
        assert!(exists<OwnerMomentumSafes>(owner), EADDRESS_NOT_REGISTRERED);
        let owned_msafes = &mut borrow_global_mut<OwnerMomentumSafes>(owner).msafes;
        let ref = table_map::borrow_mut(owned_msafes, &msafe);
        *ref = false;
        emit_register_event(owner, msafe, OP_MSAFE_MIGRATE);
    }

    #[view]
    /// Get the owner's momentum safe address list.
    /// # Parameters
    /// * `owner`: owner address.
    /// # Returns
    /// * `SimpleMap<address, bool>`: The owner's pending momentum safe address list. Map key is the momentum safe address, and map value is true.
    /// * `SimpleMap<address, bool>`: The owner's confirmed momentum safe address list. Map key is the momentum safe address, and map value of true means it keeps in MSafeV1, false means it has been migrated to MSafeV2.
    public fun get_owned_msafes(owner: address): (SimpleMap<address, bool>, SimpleMap<address, bool>) acquires OwnerMomentumSafes {
        let owned_msafes = borrow_global<OwnerMomentumSafes>(owner);
        let pendinds = utils::table_map_to_simple_map(&owned_msafes.pendings);
        let msafes = utils::table_map_to_simple_map(&owned_msafes.msafes);
        (pendinds, msafes)
    }

    #[test_only]
    /// default error code for unit test
    const E: u64 = 0;

    #[test(alice = @0xc0219135eb4067f9b957628963537bf9ae1264e18b8651e7ad27239f794ad145)]
    fun test_register(
        alice: &signer,
    ) {
        aptos_account::create_account(signer::address_of(alice));
        register(alice, x"aa0476af2f7b692ac5d04152b9ec2d15f021ed06b27076e21cd5e44e72785686");
        assert!(is_registered(signer::address_of(alice)), E);
    }

    #[test(alice = @0xc0219135eb4067f9b957628963537bf9ae1264e18b8651e7ad27239f794ad145)]
    #[expected_failure(abort_code = EADDRESS_ALREADY_REGISTERED)]
    /// Test duplicate register where the same resource cannot publish twice.
    fun test_register_duplicate(
        alice: &signer,
    ) {
        aptos_account::create_account(signer::address_of(alice));
        register(alice, x"aa0476af2f7b692ac5d04152b9ec2d15f021ed06b27076e21cd5e44e72785686");
        register(alice, x"aa0476af2f7b692ac5d04152b9ec2d15f021ed06b27076e21cd5e44e72785686");
    }

    #[test(alice = @0xa11ce)]
    #[expected_failure(abort_code = EPUBLIC_KEY_ROTATED)]
    /// The input public key does not match the user address.
    fun test_register_public_key_not_match(
        alice: &signer,
    ) {
        aptos_account::create_account(signer::address_of(alice));
        register(alice, x"aa0476af2f7b692ac5d04152b9ec2d15f021ed06b27076e21cd5e44e72785686");
    }

    #[test(alice = @0xc0219135eb4067f9b957628963537bf9ae1264e18b8651e7ad27239f794ad145)]
    fun test_verify_public_key(
        alice: &signer
    ) {
        // Postive test case
        let addr = signer::address_of(alice);
        let public_key = x"aa0476af2f7b692ac5d04152b9ec2d15f021ed06b27076e21cd5e44e72785686";
        aptos_account::create_account(addr);
        assert!(verify_public_key(addr, public_key) == true, E);

        // Negative test case
        let addr2 = @0xa11ce;
        aptos_account::create_account(addr2);
        assert!(verify_public_key(addr2, public_key) == false, E);
    }

    #[test(alice = @0xa11ce)]
    #[expected_failure(abort_code = EPUBLIC_KEY_ROTATED)]
    fun test_get_public_key_verified_rotated(
        alice: &signer,
    ) acquires OwnerMomentumSafes {
        // Setup initial public key as x"a11ce1"
        move_to(alice, OwnerMomentumSafes {
            public_key: x"a11ce1",
            pendings: table_map::create(),
            msafes: table_map::create(),
        });
        aptos_account::create_account(signer::address_of(alice));

        // Public key is different in account module and OwnerMomentumSafes,
        // thus get_public_key_verified will fail with EPUBLIC_KEY_ROTATED
        get_public_key_verified(signer::address_of(alice));
    }

    #[test_only]
    const TestMultiSig: address = @0x111;

    #[test_only]
    const TestMultiSig2: address = @0x222;

    #[test(alice = @0xa11ce)]
    fun test_confirm_pending_msafe(
        alice: &signer
    ) acquires OwnerMomentumSafes, RegisterEvent {
        // Setup
        aptos_account::create_account(signer::address_of(alice));
        move_to(alice, OwnerMomentumSafes {
            public_key: x"0000",
            pendings: table_map::from_vectors(&vector<address>[TestMultiSig], &vector<bool>[true]),
            msafes: table_map::create(),
        });
        move_to(alice, RegisterEvent {
            events: account::new_event_handle<OwnerMomentumSafesChangeEvent>(alice)
        });
        let addr = signer::address_of(alice);
        confirm_pending_msafe(addr, TestMultiSig);

        let res = borrow_global<OwnerMomentumSafes>(addr);
        assert!(table_map::length(&res.pendings) == 0, E);
        assert!(table_map::length(&res.msafes) == 1, E);
    }

    #[test(alice = @0xa11ce)]
    #[expected_failure(abort_code = EMSAFE_NOT_REGISTERED)]
    fun test_confirm_pending_msafe_not_registered(
        alice: &signer
    ) acquires OwnerMomentumSafes, RegisterEvent {
        // setup
        aptos_account::create_account(signer::address_of(alice));
        move_to(alice, OwnerMomentumSafes {
            public_key: x"0000",
            pendings: table_map::from_vectors(&vector<address>[TestMultiSig], &vector<bool>[true]),
            msafes: table_map::create(),
        });
        move_to(alice, RegisterEvent {
            events: account::new_event_handle<OwnerMomentumSafesChangeEvent>(alice)
        });

        // Check abort
        confirm_pending_msafe(signer::address_of(alice), TestMultiSig2);
    }

    #[test(alice = @0xc0219135eb4067f9b957628963537bf9ae1264e18b8651e7ad27239f794ad145)]
    fun test_add_momentum_safe(
        alice: &signer,
    ) acquires OwnerMomentumSafes, RegisterEvent {
        aptos_account::create_account(signer::address_of(alice));
        register(alice, x"aa0476af2f7b692ac5d04152b9ec2d15f021ed06b27076e21cd5e44e72785686");

        let alice = signer::address_of(alice);
        add_momentum_safe(alice, TestMultiSig);
        let addrs = &borrow_global<OwnerMomentumSafes>(alice).msafes;
        assert!(table_map::length(addrs) == 1, E);
        assert!(contain_address(addrs, TestMultiSig), E);

        add_momentum_safe(alice, TestMultiSig2);
        let addrs2 = &borrow_global<OwnerMomentumSafes>(alice).msafes;
        assert!(table_map::length(addrs2) == 2, E);
        assert!(contain_address(addrs2, TestMultiSig2), E);
    }

    #[test(alice = @0xc0219135eb4067f9b957628963537bf9ae1264e18b8651e7ad27239f794ad145)]
    /// Test adding the same msafe twice, the address will not be added twice.
    fun test_add_momentum_safe_duplicate(
        alice: &signer,
    ) acquires OwnerMomentumSafes, RegisterEvent {
        aptos_account::create_account(signer::address_of(alice));
        register(alice, x"aa0476af2f7b692ac5d04152b9ec2d15f021ed06b27076e21cd5e44e72785686");
        let alice = signer::address_of(alice);

        add_momentum_safe(alice, TestMultiSig);
        add_momentum_safe(alice, TestMultiSig);

        let addrs = &borrow_global<OwnerMomentumSafes>(alice).msafes;
        assert!(table_map::length(addrs) == 1, E);
    }

    #[test(alice = @0xc0219135eb4067f9b957628963537bf9ae1264e18b8651e7ad27239f794ad145)]
    fun test_add_pending_msafe_duplicate(
        alice: &signer,
    ) acquires OwnerMomentumSafes, RegisterEvent {
        aptos_account::create_account(signer::address_of(alice));
        register(alice, x"aa0476af2f7b692ac5d04152b9ec2d15f021ed06b27076e21cd5e44e72785686");
        let alice = signer::address_of(alice);

        add_pending_msafe(alice, TestMultiSig);
        add_pending_msafe(alice, TestMultiSig);

        let oms = borrow_global<OwnerMomentumSafes>(alice);
        assert!(table_map::length(&oms.pendings) == 1, E);
    }

    #[test]
    #[expected_failure(abort_code = EADDRESS_NOT_REGISTRERED)]
    fun test_add_momentum_safe_not_registered() acquires OwnerMomentumSafes, RegisterEvent {
        add_momentum_safe(@0xa11ce, @0x222);
    }

    #[test]
    #[expected_failure(abort_code = EADDRESS_NOT_REGISTRERED)]
    fun test_add_pending_msafe_not_registered() acquires OwnerMomentumSafes, RegisterEvent {
        add_pending_msafe(@0xa11ce, @0x222);
    }

    #[test(alice = @0xa11ce)]
    fun test_get_msafes_by_owner(
        alice: &signer
    ) acquires OwnerMomentumSafes, RegisterEvent {
        aptos_account::create_account(signer::address_of(alice));
        move_to(alice, OwnerMomentumSafes {
            public_key: x"0000",
            pendings: table_map::from_vectors(&vector<address>[TestMultiSig], &vector<bool>[true]),
            msafes: table_map::from_vectors(&vector<address>[TestMultiSig], &vector<bool>[true]),
        });
        move_to(alice, RegisterEvent {
            events: account::new_event_handle<OwnerMomentumSafesChangeEvent>(alice)
        });
        confirm_pending_msafe(signer::address_of(alice), TestMultiSig);

        let oms = borrow_global<OwnerMomentumSafes>(signer::address_of(alice));
        assert!(table_map::length(&oms.pendings) == 0, E);
        assert!(table_map::length(&oms.msafes) == 1, E);
    }

    #[test]
    #[expected_failure]
    fun test_get_msafes_by_owner_empty() acquires OwnerMomentumSafes {
        &borrow_global<OwnerMomentumSafes>(@0xa11ce).msafes;
    }

    #[test(
        alice = @0xc0219135eb4067f9b957628963537bf9ae1264e18b8651e7ad27239f794ad145,
        bob = @0x1a60afc856f9c2458435249e4297e1e606f399d5515adc38e0b10dd5c6df8393,
        charlie = @0x3b559ee3970ede1c5dd503f20b3f0d9083c16a00638d6df44ac26a3958c138c6)
    ]
    /// Test register_msafe.
    fun test_register_msafe(
        alice: &signer,
        bob: &signer,
        charlie: &signer,
    ) acquires OwnerMomentumSafes, RegisterEvent {
        // Prepare for the test - creating accounts in account.move, and register the
        // accounts to registry module.
        aptos_account::create_account(signer::address_of(alice));
        aptos_account::create_account(signer::address_of(bob));
        aptos_account::create_account(signer::address_of(charlie));
        register(alice, x"aa0476af2f7b692ac5d04152b9ec2d15f021ed06b27076e21cd5e44e72785686");
        register(bob, x"635324a9c40b651eecd6cc68adb4867d73065501a4604b774137724b80f4920d");
        register(charlie, x"547acfc3e5c6ed07d6eb67a4bebae12b9e0078edb8287891b14a971accc78c00");

        // Prepare the address vector for testing register_msafe.
        let a = signer::address_of(alice);
        let b = signer::address_of(bob);
        let c = signer::address_of(charlie);
        let v = vector::empty<address>();
        vector::push_back<address>(&mut v, a);
        vector::push_back<address>(&mut v, b);
        vector::push_back<address>(&mut v, c);

        // Mock the process - first initializing the momentum safe creation in creator,
        // and then register from `momentum_safe::register`.
        register_msafe(&v, TestMultiSig, true);
        register_msafe(&v, TestMultiSig, false);

        let multi_sigs_a = &borrow_global<OwnerMomentumSafes>(a).msafes;
        let multi_sigs_b = &borrow_global<OwnerMomentumSafes>(b).msafes;
        let multi_sigs_c = &borrow_global<OwnerMomentumSafes>(c).msafes;

        // Momentum safe is registered. All owners should have msafe of size 1.
        assert!(table_map::length(multi_sigs_a) == 1, E);
        assert!(table_map::length(multi_sigs_b) == 1, E);
        assert!(table_map::length(multi_sigs_c) == 1, E);
    }
}

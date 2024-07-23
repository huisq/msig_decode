/// Helper module used for momentum safe registration. Store the information about
/// the momentum safe registration information, and payload & signatures required
/// to call `momentum_safe.register` method.
///
/// # Why need a creator module to store the registration information?
/// Momentum safe write transaction information about pending transactions
/// (`momentum_safe::Momentum.TxnBook`) under the each momentum safe account resource
/// to maximum performance by utilizing parallel tx processing in MOVE language.
/// The data stored in `momentum_safe::Momentum` requires a initial register
/// process to publish the data, where a `move_to` operation is called with a &signer
/// object which requires the signature for the multi-sig wallet. Thus during the
/// registration process, we will need a temporary storage to store the payload and
/// signatures under a global storage as opposed to account resource. The creator
/// module serves this purpose and will write data under the deployer's address
/// for new momentum safe creations.
///
/// # The overall process walk through is as follows:
///
/// * Wallet creation initiator:
///
///     1. The wallet creation initiator collect the information about momentum safe
///         owners' addresses, threshold, momentum safe creation nonce.
///     2. Based on the momentum safe information, the owner construct the transaction
///         payload for `momentum_safe::register` off-chain. The sender of the momentum
///         safe wallet is the computed according to multi-sig address computation for
///         momentum safe.
///     3. The wallet creation initiator signs on the momentum safe register payload
///         and obtain the signature.
///     4. The wallet creation initiator submit the created momentum safe information,
///         register transaction payload, and his own signature by calling the function
///         `creator:init_wallet_creation`.
///     5. The information will be submitted on chain in `creator::MultiSigCreation`
///         under the msafe deployer's address. And the momentum safe in pending creation
///         is stored in `registry::OwnerMomentumSafes.pendings`.
///
/// * Other owners:
///
///     1. The other owners keep track of their `registry::OwnerMomentumSafes.pendings`,
///         and will be notified once a new pending wallet address is added via event
///         `Registry::RegisterEvent`.
///     2. The other owners obtain the information about the momentum safe wallet creation
///         from move resource, and sign on the payload message submitted by wallet creation
///         initiator.
///     3. The other owners submit his signature on `momentum_safe::register` transaction
///         to blockchain via calling `creator::submit_signature`
///
/// * The last owner who sign the transaction
///
///     1. The owner obtain wallet creation request from
///         `registry::OwnerMomentumSafes.pendings`, and get the wallet creation information
///         on `creator::MultiSigCreation`.
///     2. They will notice whether they are the last piece of the signature assembling
///         by comparing the collect signatures versus the momentum safe signature
///         threshold.
///     3. The last owner sign on the payload message, and assemble the multi-ed25519
///         signature with his own signature and all signatures by other owners from
///         the blockchain data.
///     4. The last owner send the transaction `momentum_safe::register` with the sender
///         momentum safe address. The signature is assembled in the last step.
///     5. The data in `momentum_safe::Momentum` is published under the momentum safe
///         resource. Momentum safe wallet is registered and can send more transactions.
///         (Please see momentum_safe.move for sending transactions)
///     6. In `momentum_safe::register`, the function will subsequently call
///         friend `registry::register_msafe` which remove the pending creation data in
///         `registry::OwnerMomentumSafes.pendings`, and added to
///         `registry::OwnerMomentumSafes.msafes`.
///     7. At this point, a momentum safe wallet is created successfully.
module msafe::creator {
    use std::signer;
    use std::vector;

    use aptos_framework::account;
    use aptos_framework::aptos_account;
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::coin;
    use aptos_std::event::{Self, EventHandle};
    use aptos_std::simple_map::{Self, SimpleMap};
    use aptos_std::table::{Self, Table};

    use msafe::registry;
    use msafe::transaction;
    use msafe::utils;

    #[test_only]
    use aptos_framework::timestamp;
    use aptos_framework::chain_id;

    friend msafe::momentum_safe;
    #[test_only]
    friend msafe::test_suite;

    /// Deployer account to store all data in creator module.
    const THIS: address = @msafe;

    // Error codes

    /// Signature verify failed
    const ESIGNATURE_VERIFY_FAILED: u64 = 1;

    /// Number of owners should be greater than one
    const EOWNERS_LESS_THAN_TWO: u64 = 2;

    /// Wallet signature threshold is bigger than the number of public keys
    const ETHRESHOLD_BEYOND_PUBLIC_KEYS: u64 = 3;

    /// Msafe wallet creator must be the first in the owner list where we obtain
    /// the wallet creation nonce from.
    const ESIGNER_MUST_FIRST_OWNER: u64 = 4;

    /// Sender of msafe-tx must be msafe address
    const EMSAFE_TX_SENDER_INVALID: u64 = 5;

    /// Sequence number of msafe-tx is invalid.
    const EMSAFE_TX_SEQUENCE_NUMBER_INVALID: u64 = 6;

    /// Momentum safe creation transaction is already expired.
    const EMSAFE_TX_EXPIRED: u64 = 7;

    /// Trying to prune a creation that is not expired.
    const EMSAFE_TX_NOT_EXPIRED: u64 = 8;

    /// Module ID decoded from the creation transaction payload is not as expected.
    const EMSAFE_TX_MODULE_INVALID: u64 = 9;

    /// Function decoded from the creation transaction payload is not as expected.
    const EMSAFE_TX_FUNCTION_INVALID: u64 = 10;

    /// Invalid max-gas decoded from the creation transaction payload.
    const EMSAFE_TX_GAS_INVALID: u64 = 11;

    /// Invalid gas price decoded form the creation transaction payload.
    const EMSAFE_TX_GAS_PRICE_INVALID: u64 = 12;

    /// INIT_BALANCE is less than the gas requried for the registering a momentum
    /// safe.
    const EMSAFE_INIT_BALANCE_INSUFFICIENT: u64 = 13;

    /// Number of owners exceed MAX_MSAFE_OWNERS_LIMIT
    const EMSAFE_OWNERS_EXCEED_LIMIT: u64 = 14;

    /// Momentum safe is not found in creator module.
    const EMSAFE_NOT_FOUND: u64 = 15;

    /// Sequence number of a new msafe account must be 0.
    const ESEQUENCE_NUMBER_MUST_ZERO: u64 = 16;

    /// Exist duplicate public key.
    const EEXIST_DUPLICATE_PUBLIC_KEY: u64 = 17;

    /// Exist duplicate public key.
    const EMSAFE_TX_CHAINID_INVALID: u64 = 18;
    /// First valid nonce must be zero.
    const EMSAFE_INIT_NONCE_INVALID: u64 = 19;
    /// First valid nonce must be zero.
    const EMSAFE_IMPORTED_MSAFE_AUTHKEY_INVALID: u64 = 20;

    /// Threshold of a multi-sign wallet can't be zero.
    const ETHRESHOLD_IS_ZERO: u64 = 21;

    /// gas fields required by register tx.
    /// The parameters are used to check whether the deserialized transaction
    /// parameters meets the minimum requirement of a gas situation.
    /// The gas is subject to change according to be updated according to
    /// the real-time network situation.
    const MIN_REGISTER_TX_GAS: u64 = 2000;
    const MIN_REGISTER_TX_GAS_PRICE: u64 = 1;
    /// Limit on the number of public keys in the Aptos multi-sign wallet scheme.
    const MAX_APTOS_MULTISIGN_PUBLIC_KEYS_LIMIT: u64 = 32;
    /// When use msafe to create a multi-sign wallet, the last public key is used for the creation nonce,
    /// which is a public key that no one own it's private key.
    /// so the maximum number of owners of a msafe wallet is MAX_APTOS_MULTISIGN_PUBLIC_KEYS_LIMIT - 1 = 31.
    const MAX_MSAFE_OWNERS_LIMIT: u64 = 32 - 1;
    const MAX_U64: u64 = 0xffffffffffffffff;

    /// Wallet creation information stored under the deployer's account.
    struct PendingMultiSigCreations has key {
        // A map from address to its counter. For each momentum safe creation
        // request, the first owner's nonce is used for momontum safe public
        // address computation. Please check out `utils::derive_multisig_auth_key`
        // for detailed information about momentum safe public key computation.
        nonces: Table<address, u64>,
        // A map from momentum safe address to its pending creation data structure.
        // Storing information about momentum safe wallet information and collects
        // signatures & payload for `momentum_safe::register`.
        creations: Table<address, MomentumSafeCreation>,
    }

    /// Event handler for new momentum safe creation.
    /// Emit a event of `MultiSigCreation` when there is a new wallet creation request
    /// is submitted.
    struct MultiSigCreationEvent has key {
        events: EventHandle<MomentumSafeCreation>
    }

    /// Detailed information of the multi-sig creation process.
    ///     1. information about momentum safe wallet, including owners, public keys,
    ///         creation nonce, and threshold.
    ///     2. Transaction payload and signature collected.
    struct MomentumSafeCreation has store, drop, copy {
        // vector of public_keys
        owners: vector<address>,
        public_keys: vector<vector<u8>>,
        nonce: u64,
        threshold: u8,
        txn: CreateWalletTxn,
    }

    /// Store transaction information included in momentum safe registration.
    ///     1. Encoded transaction payload for momentum_safe.register.
    ///     2. Signatures collected so far, indexed with owner public keys.
    struct CreateWalletTxn has store, drop, copy {
        payload: vector<u8>,
        // public_key => signature
        signatures: SimpleMap<vector<u8>, vector<u8>>,
    }

    /// Contract initializer. automatically called when deployed or upgraded.
    /// Publish the initial `PendingMultiSigCreation` structure under the deployer's
    /// resource.
    ///
    /// # Parameters
    /// * `creator`: signer object of the move module creator.
    fun init_module(
        creator: &signer
    ) {
        let init_nonce = utils::next_valid_nonce_public_key(0, signer::address_of(creator));
        assert!(init_nonce == 0, EMSAFE_INIT_NONCE_INVALID);
        // for upgarade
        if (!exists<PendingMultiSigCreations>(signer::address_of(creator))) {
            move_to(creator, PendingMultiSigCreations {
                nonces: table::new(),
                creations: table::new(),
            });
            move_to(creator, MultiSigCreationEvent {
                events: account::new_event_handle<MomentumSafeCreation>(creator)
            })
        }
    }

    /// Initiate a wallet creation request.
    ///
    /// The first of the momentum safe owners will initiate a wallet creation
    /// and fill in all required fields for momentum safe creation.
    ///
    /// # Parameters
    /// * `s`: signer of the transaction. The signer is required to be the owner
    ///         of the first public key.
    /// * `owners`: address of the owners. The system will check out the public
    ///         keys from the registry from each owner.
    /// * `threshold`: Signing threshold. Must be a value between zero and number
    ///         of owners.
    /// * `init_balance`: The init balance send from the creation initiator to
    ///         momentum safe wallet used for paying the gas fees of
    ///         `momentum_safe::register`. The value must be greater than the
    ///         gas fee settings from transaction payload deserialization.
    /// * `payload`: The transaction payload for `momentum_safe::register`.
    ///         The payload will be deserialized and verify whether the transaction
    ///         is able to be executed.
    /// * `signature`: Creation initiator's ed25519 signature on the transaction
    ///         payload. The signature is checked against creator's public key and
    ///         signing message (payload).
    ///
    /// # Aborts
    /// * `EOWNERS_LESS_THAN_TWO`
    /// * `ETHRESHOLD_BEYOND_PUBLIC_KEYS`
    /// * `registry::EADDRESS_NOT_REGISTRERED`
    /// * `registry::EPUBLIC_KEY_ROTATED`
    /// * `ESIGNER_MUST_FIRST_OWNER`
    /// * `transaction::EBUFFER_OVERFLOW`
    /// * `transaction::ENUMBER_OVERFLOW`
    /// * `EMSAFE_TX_SENDER_INVALID`
    /// * `EMSAFE_TX_SEQUENCE_NUMBER_INVALID`
    /// * `EMSAFE_TX_EXPIRED`
    /// * `EMSAFE_TX_MODULE_INVALID`
    /// * `EMSAFE_TX_FUNCTION_INVALID`
    /// * `EMSAFE_TX_GAS_INVALID`
    /// * `EMSAFE_TX_GAS_PRICE_INVALID`
    /// * `EMSAFE_INIT_BALANCE_INSUFFICIENT`
    /// * `EMSAFE_OWNERS_EXCEED_LIMIT`
    /// * `EMSAFE_NOT_FOUND`: Momentum safe is not found in creator module
    /// * `ESEQUENCE_NUMBER_MUST_ZERO`
    /// * `EEXIST_DUPLICATE_PUBLIC_KEY`
    /// * `EMSAFE_TX_CHAINID_INVALID`
    ///
    /// # Emits
    /// * `MultiSigCreationEvent`: New momentum safe creation request is submitted
    ///         successfully.
    public entry fun init_wallet_creation(
        s: &signer,
        owners: vector<address>,
        threshold: u8,
        init_balance: u64,
        payload: vector<u8>,
        signature: vector<u8>,
    ) acquires PendingMultiSigCreations, MultiSigCreationEvent {
        init_wallet_creation_internal(
            s,
            owners,
            threshold,
            init_balance,
            payload,
            signature,
            THIS,
        )
    }

    /// Initiate a multisig-wallet import request.
    ///
    /// Import a multisig-wallet which not create by this contract. The nonce of MomentumSafeCreation of imported wallet is MAX_U64.
    ///
    /// # Parameters
    /// * `s`: signer of the transaction. The signer is required to be the owner
    ///         of the first public key.
    /// * `account_import`: multisig account want to import
    /// * `owners`: address of the owners. The system will check out the public
    ///         keys from the registry from each owner.
    /// * `ext_public_keys`: public keys without private keys, but can be used to generate authkey of multisig account
    /// * `threshold`: Signing threshold. Must be a value between zero and number
    ///         of owners.
    /// * `payload`: The transaction payload for `momentum_safe::register`.
    ///         The payload will be deserialized and verify whether the transaction
    ///         is able to be executed.
    /// * `signature`: Creation initiator's ed25519 signature on the transaction
    ///         payload. The signature is checked against creator's public key and
    ///         signing message (payload).
    ///
    /// # Emits
    /// * `MultiSigCreationEvent`: New momentum safe creation request is submitted
    ///         successfully.
    public entry fun init_wallet_import(
        s: &signer,
        account_import: address,
        owners: vector<address>,
        threshold: u8,
        init_balance: u64,
        payload: vector<u8>,
        pk_index: u8,
        signature: vector<u8>,
    ) acquires PendingMultiSigCreations, MultiSigCreationEvent {
        init_wallet_import_internal(s, account_import, owners, threshold, init_balance, payload, pk_index, signature, THIS)
    }

    public(friend) fun init_wallet_import_internal(
        s: &signer,
        account_import: address,
        owners: vector<address>,
        threshold: u8,
        init_balance: u64,
        payload: vector<u8>,
        pk_index: u8,
        signature: vector<u8>,
        module_address: address,
    ) acquires PendingMultiSigCreations, MultiSigCreationEvent {
        let public_keys = get_public_keys_and_check(&owners, MAX_APTOS_MULTISIGN_PUBLIC_KEYS_LIMIT, threshold);
        let auth_key_expected = utils::multisig_public_keys_to_auth_key(public_keys, threshold);
        // account_import should already be created, but if it isn't, we still create it.
        if (!account::exists_at(account_import)) {
            aptos_account::create_account(account_import);
        };
        assert!(auth_key_expected == account::get_authentication_key(account_import), EMSAFE_IMPORTED_MSAFE_AUTHKEY_INVALID);
        validate_register_payload(payload, account_import, module_address, init_balance);
        assert!(vector::length(&public_keys) <= MAX_APTOS_MULTISIGN_PUBLIC_KEYS_LIMIT, EMSAFE_OWNERS_EXCEED_LIMIT);
        coin::transfer<AptosCoin>(s, account_import, init_balance);

        // Write data for new momentum safe creation
        store_creation(MomentumSafeCreation {
            owners,
            public_keys,
            nonce: MAX_U64,
            threshold,
            txn: CreateWalletTxn {
                payload,
                signatures: simple_map::create(),
            }
        }, account_import, pk_index, signature);
    }

    fun store_creation(creation: MomentumSafeCreation, msafe_address: address, pk_index: u8, signature: vector<u8>) acquires PendingMultiSigCreations, MultiSigCreationEvent {
        add_signature(&mut creation, pk_index, signature);
        let owners = creation.owners;
        let pending = borrow_global_mut<PendingMultiSigCreations>(THIS);
        table::add(&mut pending.creations, msafe_address, creation);
        add_to_registry(&owners, msafe_address);

        // Emit the event of new creation.
        let event_handle = borrow_global_mut<MultiSigCreationEvent>(THIS);
        event::emit_event(
            &mut event_handle.events,
            move creation
        )
    }

    /// Submit a transaction signature for a wallet creation request.
    ///
    /// After the initiator initiates the momentum safe creation request, the
    /// other owners need to sign on the register payload to prove the creation
    /// of momentum safe.
    ///
    /// # Parameters
    /// * `msafe_address`: momentum safe address to approve.
    /// * `pk_index`: index of the msafe_address in the owner vector.
    /// * `signature`: signature on the register payload.
    ///
    /// # Aborts
    /// * `simple_map::EKEY_NOT_FOUND`: The creation request of msafe_address is not
    ///         received.
    /// * `ESIGNATURE_VERIFY_FAILED`: signature fails ed25519 check.
    ///
    /// # Emits
    /// * `MultiSigCreationEvent`: new creation data if a new signature is added.
    public entry fun submit_signature(
        msafe_address: address,
        pk_index: u8,
        signature: vector<u8>,
    ) acquires PendingMultiSigCreations, MultiSigCreationEvent {
        let pending = borrow_global_mut<PendingMultiSigCreations>(THIS);
        let creation = table::borrow_mut(
            &mut pending.creations, msafe_address
        );
        add_signature(creation, pk_index, signature);

        // Emit the event about signature update.
        let event_handle = borrow_global_mut<MultiSigCreationEvent>(THIS);
        event::emit_event(
            &mut event_handle.events,
            *creation
        )
    }

    /// Clean an expired contract creation request from `PendingMultiSigCreations`.
    ///
    /// Some momentum safe creation transaction will be expired, and can never be
    /// executed. clean_expired_creation adds a cleaning mechanism to prune
    /// pending creations that can never be executed. This will help reduce some
    /// unnecessary storage on chain storage. If the transaction is not expired,
    /// the prune cannot be executed.
    ///
    /// Any account can call this function to prune stale transactions. But normally
    /// it's the momentum safe keeper that have the largest initiatives to clear
    /// expired pending creations.
    ///
    /// # Parameters
    /// * `msafe_addresses`: vector of msafe addresses to be pruned.
    ///
    /// # Aborts
    /// * `EMSAFE_TX_NOT_EXPIRED`: try to prune an unexpired momentum safe creation.
    public entry fun clean_expired_creation(
        msafe_addresses: vector<address>
    ) acquires PendingMultiSigCreations {
        while (!vector::is_empty(&msafe_addresses)) {
            let msafe_address = vector::pop_back(&mut msafe_addresses);

            // It is ok to remove the creation first since the transaction
            // in vm is atomic.
            let (_, creation) = remove_wallet_creation(msafe_address);
            let register_transaction = transaction::decode_transaction(creation.txn.payload);
            let expiration_timestamp = transaction::get_expiration_timestamp_secs(&register_transaction);

            // abort if removing an unexpired transaction.
            assert!(expiration_timestamp < utils::now_seconds(), EMSAFE_TX_NOT_EXPIRED);
        }
    }

    /// Compute the momentum safe address.
    ///
    /// The computation requires three elements: public keys, creation nonce,
    /// and threshold. In this function, the creation nonce is also incremented
    /// for the creator stored in `PendingMultiSigCreations`.
    ///
    /// # Parameters
    /// * `pendings`: mutable reference to storage `PendingMultiSigCreations`.
    /// * `creator`: the address for creation initiator. Used to get and increment
    ///         nonce.
    /// * `public_keys`: public keys of the momentum safe creation.
    /// * `threhsold`: signing threhsold of the momentum safe.
    /// * `module_address`: module_address used to generate public key with the nonce.
    ///
    /// # Returns
    /// * `address`: the computed momentum safe address.
    /// * `u64`: nonce used to compute the momentum safe address.
    fun derive_new_multisig_auth_key(
        pending: &mut PendingMultiSigCreations,
        creator: address,
        public_keys: vector<vector<u8>>,
        threshold: u8,
        module_address: address
    ): (
        address,
        u64
    ) {
        if (!table::contains(&pending.nonces, creator)) {
            // init_nonce should be zero, it's already been checked in init_module.
            let init_nonce = utils::next_valid_nonce_public_key(0, module_address);
            table::add(&mut pending.nonces, creator, init_nonce);
        };
        let nonce_ptr = table::borrow_mut(&mut pending.nonces, creator);
        let cur_nonce = *nonce_ptr;
        let auth_key = utils::derive_multisig_auth_key(
            public_keys, threshold, cur_nonce, module_address
        );
        // always save next valid nonce to store
        *nonce_ptr = utils::next_valid_nonce_public_key(cur_nonce + 1, module_address);
        (utils::address_from_bytes(auth_key), cur_nonce)
    }

    /// Verifies the signature and add to `MultiSigCreation`.
    ///
    /// # Parameters
    /// * `creation`: Momentum safe creation data.
    /// * `pk_index`: The index of the owner giving signature.
    /// * `signature`: signature to be added.
    ///
    /// # Aborts
    /// * `ESIGNATURE_VERIFY_FAILED`: signature verification fails.
    fun add_signature(
        creation: &mut MomentumSafeCreation,
        pk_index: u8,
        signature: vector<u8>
    ) {
        let public_key = *vector::borrow(&creation.public_keys, (pk_index as u64));
        verify_signature(signature, public_key, creation.txn.payload);
        simple_map::add(&mut creation.txn.signatures, public_key, signature);
    }

    /// Verifies the signature from public_key on message.
    ///
    /// # Parameters
    /// * `signature`: signature to be verified.
    /// * `public_key`: public key of the signer.
    /// * `message`: signing message.
    ///
    /// # Aborts
    /// * `ESIGNATURE_VERIFY_FAILED`: signature fails the verification.
    fun verify_signature(
        signature: vector<u8>,
        public_key: vector<u8>,
        message: vector<u8>
    ) {
        let succcess = utils::verify_signature(signature, public_key, message);
        assert!(succcess, ESIGNATURE_VERIFY_FAILED);
    }

    /// Get the `PendingMultiSigCreations` from the given address.
    ///
    /// # Parameters
    /// * `msafe_address`: address to query.
    ///
    /// # Returns
    /// * `vector<address>`: owner addresses.
    /// * `vector<vector<u8>>`: public keys.
    /// * `u64`: creation nonce.
    /// * `u8`: creation threshold.
    ///
    /// # Aborts
    /// * `EMSAFE_NOT_FOUND`: momentum safe creation data is not found.
    public fun get_creation(
        msafe_address: address
    ): (
        vector<address>,
        vector<vector<u8>>,
        u64,
        u8
    ) acquires PendingMultiSigCreations {
        let pending = borrow_global<PendingMultiSigCreations>(THIS);
        assert!(table::contains(&pending.creations, msafe_address), EMSAFE_NOT_FOUND);
        let creation = table::borrow(&pending.creations, msafe_address);
        (creation.owners, creation.public_keys, creation.nonce, creation.threshold)
    }

    /// Remove the pending wallet creation from `PendingMultiSigCreations`.
    /// Called by `momentum_safe.register` after successfully register the momentum
    /// safe wallet.
    ///
    /// # Parameters
    /// * `msafe_address`: momentum safe wallet address to be removed.
    ///
    /// # Returns
    /// * `address`: address being removed.
    /// * `MultiSigCreation`: Removed creation info.
    public(friend) fun remove_wallet_creation(
        msafe_address: address
    ): (
        address,
        MomentumSafeCreation
    ) acquires PendingMultiSigCreations {
        let pending = borrow_global_mut<PendingMultiSigCreations>(THIS);
        (msafe_address, table::remove(&mut pending.creations, msafe_address))
    }

    /// Internal function call to init wallet. Used for public entry init_wallet_creation
    /// and unit tests.
    ///
    /// # Parameters
    /// * `s`: signer of the transaction. The signer is required to be the owner
    ///         of the first public key.
    /// * `owners`: address of the owners. The system will check out the public
    ///         keys from the registry from each owner.
    /// * `threshold`: Signing threshold. Must be a value between zero and number
    ///         of owners.
    /// * `init_balance`: The init balance send from the creation initiator to
    ///         momentum safe wallet used for paying the gas fees of
    ///         `momentum_safe::register`. The value must be greater than the
    ///         gas fee settings from transaction payload deserialization.
    /// * `payload`: The transaction payload for `momentum_safe::register`.
    ///         The payload will be deserialized and verify whether the transaction
    ///         is able to be executed.
    /// * `signature`: Creation initiator's ed25519 signature on the transaction
    ///         payload. The signature is checked against creator's public key and
    ///         signing message (payload).
    /// * `module_address`: module address for deployer. The module address is encoded
    ///         in transaction payload and used in unit tests.
    ///
    /// # Aborts
    /// * `EOWNERS_LESS_THAN_TWO`: Number of owners is 1.
    /// * `ETHRESHOLD_BEYOND_PUBLIC_KEYS`: Invalid threshold.
    /// * `registry::EADDRESS_NOT_REGISTRERED`: The owner has not been registered
    ///         in registry.
    /// * `registry::EPUBLIC_KEY_ROTATED`: The public key stored in registry does
    ///         not match that from account.move.
    ///
    /// * `ESIGNER_MUST_FIRST_OWNER`: The signer is not the first owner of the
    ///         momentum safe information.
    /// * `transaction::EBUFFER_OVERFLOW`, `transaction::ENUMBER_OVERFLOW`: Invalid
    ///         transaction payload.
    /// * `EMSAFE_TX_SENDER_INVALID`: The sender decoded from the transaction payload
    ///         does not match momentum safe address.
    /// * `EMSAFE_TX_SEQUENCE_NUMBER_INVALID`: Stale sequence number decoded from the
    ///         transaction payload.
    /// * `EMSAFE_TX_EXPIRED`: Transaction is already expired in expiration timestamp.
    /// * `EMSAFE_TX_MODULE_INVALID`: According to ransaction payload, the creation
    ///         is not calling move module `@msafe::momentum_safe`.
    /// * `EMSAFE_TX_FUNCTION_INVALID`: According to transaction payload, the creation
    ///         is not calling move function `register`
    /// * `EMSAFE_TX_GAS_INVALID`: Invalid max_gas_amount settings.
    /// * `EMSAFE_TX_GAS_PRICE_INVALID`: Invalid gas price settings.
    /// * `EMSAFE_INIT_BALANCE_INSUFFICIENT`: Init balance is not enough for paying
    ///         gas fees for momentum safe registration.
    ///
    /// # Emits
    /// * `MultiSigCreationEvent`: New momentum safe creation request is submitted
    ///         successfully.
    public(friend) fun init_wallet_creation_internal(
        s: &signer,
        owners: vector<address>,
        threshold: u8,
        init_balance: u64,
        payload: vector<u8>,
        signature: vector<u8>,
        module_address: address,
    ) acquires PendingMultiSigCreations, MultiSigCreationEvent {
        // Check the input parameters.
        let public_keys = get_public_keys_and_check(&owners, MAX_MSAFE_OWNERS_LIMIT, threshold);
        let creator = vector::borrow(&owners, 0);
        // calculate the momentum safe address and increment the nonce.
        let pending = borrow_global_mut<PendingMultiSigCreations>(THIS);
        let (msafe_address, nonce) = derive_new_multisig_auth_key(
            pending, *creator, public_keys, threshold, module_address
        );
        validate_register_payload(payload, msafe_address, module_address, init_balance);

        // Create the momentum safe wallet and send the initial fund for gas fee.
        if (!account::exists_at(msafe_address)) {
            aptos_account::create_account(msafe_address);
        };
        assert!(account::get_sequence_number(msafe_address) == 0, ESEQUENCE_NUMBER_MUST_ZERO);
        coin::transfer<AptosCoin>(s, msafe_address, init_balance);

        // Write data for new momentum safe creation
        // signature should be verified by the first public key. This also ensures that creator is the first owner
        store_creation(MomentumSafeCreation {
            owners,
            public_keys,
            nonce,
            threshold,
            txn: CreateWalletTxn {
                payload,
                signatures: simple_map::create(),
            }
        }, msafe_address, 0, signature);
    }

    fun get_public_keys_and_check(owners: &vector<address>, max_owner_limit: u64, threshold: u8): vector<vector<u8>> {
        // Check the input parameters.
        let owners_count = vector::length(owners);
        assert!(owners_count > 1, EOWNERS_LESS_THAN_TWO);
        assert!(owners_count <= max_owner_limit, EMSAFE_OWNERS_EXCEED_LIMIT);
        assert!((threshold as u64) <= owners_count, ETHRESHOLD_BEYOND_PUBLIC_KEYS);
        assert!(threshold > 0, ETHRESHOLD_IS_ZERO);

        let public_keys = get_public_keys(owners);
        assert!(utils::vector_dup_exist(&public_keys) == false, EEXIST_DUPLICATE_PUBLIC_KEY);
        public_keys
    }

    /// Add the momentum safes under pending creation to registry.
    ///
    /// # Parameters
    /// * `owners`: owner address vector.
    /// * `msafe`: created msafe address to be registered.
    ///
    /// # Aborts
    /// * `registry::EADDRESS_NOT_REGISTRERED`: address not registered.
    fun add_to_registry(
        owners: &vector<address>,
        msafe: address
    ) {
        registry::register_msafe(owners, msafe, true);
    }

    /// Validates the payload for registry function.
    ///
    /// # Parameters
    /// * `payload`: transaction payload to be deserialized.
    /// * `msafe_address`: momentum safe address.
    /// * `module_address`: module address of momentum_safe.
    /// * `init_balance`: Initial balance sent to the momentum safe wallet for gas fees.
    ///
    /// # Aborts
    /// * `transaction::EBUFFER_OVERFLOW`, `transaction::ENUMBER_OVERFLOW`: Invalid
    ///         transaction payload
    /// * `EMSAFE_TX_SENDER_INVALID`: The sender decoded from the transaction payload
    ///         does not match momentum safe address.
    /// * `EMSAFE_TX_SEQUENCE_NUMBER_INVALID`: Stale sequence number decoded from the
    ///         transaction payload.
    /// * `EMSAFE_TX_EXPIRED`: Transaction is already expired in expiration timestamp.
    /// * `EMSAFE_TX_MODULE_INVALID`: According to ransaction payload, the creation
    ///         is not calling move module `@msafe::momentum_safe`.
    /// * `EMSAFE_TX_FUNCTION_INVALID`: According to transaction payload, the creation
    ///         is not calling move function `register`
    /// * `EMSAFE_TX_GAS_INVALID`: Invalid max_gas_amount settings.
    /// * `EMSAFE_TX_GAS_PRICE_INVALID`: Invalid gas price settings.
    /// * `EMSAFE_INIT_BALANCE_INSUFFICIENT`: Init balance is not enough for paying
    ///         gas fees for momentum safe registration.
    fun validate_register_payload(
        payload: vector<u8>,
        msafe_address: address,
        module_address: address,
        init_balance: u64,
    ) {
        let register_transaction = transaction::decode_transaction(payload);

        let sender = transaction::get_sender(&register_transaction);
        assert!(sender == msafe_address, EMSAFE_TX_SENDER_INVALID);

        let tx_chain_id = transaction::get_chain_id(&register_transaction);
        assert!(tx_chain_id == chain_id::get(), EMSAFE_TX_CHAINID_INVALID);

        let tx_sn = transaction::get_sequence_number(&register_transaction);
        let sender_sn = if (account::exists_at(sender)) { account::get_sequence_number(sender) } else { 0 };
        assert!(tx_sn == sender_sn, EMSAFE_TX_SEQUENCE_NUMBER_INVALID);

        let exp = transaction::get_expiration_timestamp_secs(&register_transaction);
        assert!(exp > utils::now_seconds(), EMSAFE_TX_EXPIRED);

        let (module_addr, module_name) = transaction::get_module_name(&register_transaction);
        assert!(module_addr == module_address, EMSAFE_TX_MODULE_INVALID);
        assert!(module_name == b"momentum_safe", EMSAFE_TX_MODULE_INVALID);

        let fun_name = transaction::get_function_name(&register_transaction);
        assert!(fun_name == b"register", EMSAFE_TX_FUNCTION_INVALID);

        let max_gas_amount = transaction::get_max_gas_amount(&register_transaction);
        let gas_unit_price = transaction::get_gas_unit_price(&register_transaction);
        assert!(max_gas_amount >= MIN_REGISTER_TX_GAS, EMSAFE_TX_GAS_INVALID);
        assert!(gas_unit_price >= MIN_REGISTER_TX_GAS_PRICE, EMSAFE_TX_GAS_PRICE_INVALID);
        assert!(max_gas_amount * gas_unit_price <= init_balance, EMSAFE_INIT_BALANCE_INSUFFICIENT);
    }

    /// Get the public key from registry for the addresses
    ///
    /// # Parameters
    /// * `owners`: address vector to query for public keys.
    ///
    /// # Returns
    /// * `vector<vector<u8>>`: public keys
    ///
    /// # Aborts
    /// * `registry::EADDRESS_NOT_REGISTRERED`: The account hasn't been registered
    ///         before.
    /// * `registry::EPUBLIC_KEY_ROTATED`: The account's public key is different
    ///         from what was previously stored during registration.
    fun get_public_keys(
        owners: &vector<address>
    ): vector<vector<u8>> {
        let public_keys = vector::empty<vector<u8>>();
        let i = 0;
        while (i < vector::length(owners)) {
            let owner = *vector::borrow(owners, i);
            vector::push_back(&mut public_keys, registry::get_public_key_verified(owner));
            i = i + 1
        };
        public_keys
    }

    # [test_only]
    const E: u64 = 0;
    # [test_only]
    const CHAIN_ID_FOR_TEST: u8 = 0x1f;

    #[test_only]
    const TEST_REGISTER_TX_PAYLOAD: vector<u8> = x"b5e97db07fa0bd0e5598aa3643a9bc6f6693bddc1a9fec9e674a461eaa00b193c0455c582b0e3d794918db7de1f1c218ac311701db218958718e74494703fd3b0000000000000000024cebef114d8ce88cc1e1df73b9a6effa51bf58105b18e2be2dc222c84a3e54850d6d6f6d656e74756d5f7361666508726567697374657200010d0c68656c6c6f206d2d73616665d0070000000000000100000000000000d0e22663000000001f";

    #[test_only]
    const OWNER_PUBLIC_KEY: vector<u8> = x"fb2c62d2ab98f1e6454a83ec0b7a2102a3d6b84d6c6d89ec013ba544f823345a";

    #[test_only]
    const OWNER_REGISTER_TX_SIGNATURE: vector<u8> = x"40e66eda2884c6e9cb639dcc4b4c85d45a98583b1ad37c1a3df52be23a6b22cf20647eb4c9ac03469ef3c5567f021e5b032e8fd0d0a5b9f1faae23ee9b1eea01";

    # [test_only]
    const SIGNATURE_INVALID: vector<u8> = x"1111b0a36be89cec78f710bd139620bae9c5ea3b003641a98a079f38fea73b66bb830df49ff1df9cbc9d268d412ad08324e2401ef8cf008b7c4abf097b284203";

    # [test_only]
    const OWNER_PUBLIC_KEY2: vector<u8> = x"f35efdbaf43b84fde165722ec0bf0677c2aa3c4e682ad09dae57ffeaf6351b2d";

    # [test_only]
    const OWNER_PUBLIC_KEY3: vector<u8> = x"2c7a0e2b666900dbcca041516cdda75e57fffc06a1103cd4da21f026f1ab63b5";

    #[test_only]
    public fun init_test(
        s: &signer
    ) {
        aptos_account::create_account(signer::address_of(s));
        init_module(s)
    }

    #[test_only]
    public fun exist_creation(
        msafe_addres: address
    ): bool acquires PendingMultiSigCreations {
        let pending = borrow_global<PendingMultiSigCreations>(THIS);
        table::contains(&pending.creations, msafe_addres)
    }

    #[test(s = @msafe_invalid)]
    #[expected_failure(abort_code = EMSAFE_INIT_NONCE_INVALID)]
    fun test_init_abort(s: &signer) {
        init_test(s)
    }

    #[test(s = @msafe)]
    fun test_derive_new_multisig_auth_key(s: &signer) acquires PendingMultiSigCreations {
        init_test(s);
        let expected_addresses = vector<address>
            [
                @msafe_wallet,
                @0xa5ea24655a314868e699d33bfedca4c06ec8fd6f1bf10a90f45995baacf66a64,
                @0xba4aa1469b776ad7e53b5963018b04396268e4dbb73672efc6dcdf42a8153b33,
                @0xfb37bdaf6659c95cd69e98c9519916a0da5decc4367028998ce4be7c42091472,
                @0x9f0c87269125118192041007a012c05cac9c3cb83a27579b7f562694441b6789,
                @0xb917f79684283709f18a960287f175286759911b4e1924e038db1a799be69acf,
                @0x3e19a2413625cfdb78d3d1a85165f6d631c9575fc148a937f8abc161a12428fe,
                @0xa01f7db274583da429b22fc1732f9fc9e6665997782c7ccb00d18e5a81539a85,
                @0x3ea5235c62c842cb3bb09aef01e6314da19cb8c499fe5db150dbbe6007ec670f,
                @0x4b6a47edd60e0aab07756721842d893acb1d09031f5da15c77bc306ae093f0fc,
            ];
        let expected_nonces = vector<u64>[0, 1, 2, 3, 4, 5, 8, 14, 15, 20];
        let public_keys = vector<vector<u8>>
            [
                OWNER_PUBLIC_KEY,
                OWNER_PUBLIC_KEY2,
                OWNER_PUBLIC_KEY3,
            ];
        let pending = borrow_global_mut<PendingMultiSigCreations>(THIS);
        let i = 0;
        while (i < 10) {
            let (address, nonce) = derive_new_multisig_auth_key(pending, @0x12, public_keys, 2, @test_msafe_module);
            let expected_address = *vector::borrow(&expected_addresses, i);
            assert!(address == expected_address, E);
            let expected_nonce = *vector::borrow(&expected_nonces, i);
            assert!(nonce == expected_nonce, E);
            i = i + 1;
        }
    }

    #[test]
    fun test_add_signature() {
        let payload = TEST_REGISTER_TX_PAYLOAD;
        let signature = OWNER_REGISTER_TX_SIGNATURE;
        let public_key = OWNER_PUBLIC_KEY;
        let creation = MomentumSafeCreation {
            owners: vector<address>[],
            public_keys: vector<vector<u8>>[public_key],
            nonce: 0,
            threshold: 0,
            txn: CreateWalletTxn {
                payload,
                signatures: simple_map::create()
            },
        };
        add_signature(&mut creation, 0, signature);
        assert!(simple_map::contains_key(&creation.txn.signatures, &public_key), E)
    }

    #[test]
    #[expected_failure (abort_code = ESIGNATURE_VERIFY_FAILED)]
    fun test_add_invalid_signature() {
        let payload = TEST_REGISTER_TX_PAYLOAD;
        let signature_invalid = SIGNATURE_INVALID;
        let public_key = OWNER_PUBLIC_KEY;
        let creation = MomentumSafeCreation {
            owners: vector<address>[],
            public_keys: vector<vector<u8>>[public_key],
            nonce: 0,
            threshold: 0,
            txn: CreateWalletTxn {
                payload,
                signatures: simple_map::create()
            },
        };
        add_signature(&mut creation, 0, signature_invalid)
    }

    #[test(aptos_framework = @aptos_framework)]
    fun test_check_register_payload(
        aptos_framework: &signer
    ) {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        chain_id::initialize_for_test(aptos_framework, CHAIN_ID_FOR_TEST);
        aptos_account::create_account(@msafe_wallet);
        let payload = TEST_REGISTER_TX_PAYLOAD;
        validate_register_payload(payload, @msafe_wallet, @test_msafe_module, 10000)
    }

    #[test(aptos_framework = @aptos_framework)]
    #[expected_failure(abort_code = EMSAFE_INIT_BALANCE_INSUFFICIENT)]
    fun test_check_register_payload_insufficient_balance(
        aptos_framework: &signer
    ) {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        chain_id::initialize_for_test(aptos_framework, CHAIN_ID_FOR_TEST);
        aptos_account::create_account(@msafe_wallet);
        let payload = TEST_REGISTER_TX_PAYLOAD;
        validate_register_payload(payload, @msafe_wallet, @test_msafe_module, 100)
    }

    #[test(aptos_framework = @aptos_framework)]
    #[expected_failure(abort_code = EMSAFE_TX_MODULE_INVALID)]
    fun test_check_register_payload_wrong_module(
        aptos_framework: &signer
    ) {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        chain_id::initialize_for_test(aptos_framework, CHAIN_ID_FOR_TEST);
        aptos_account::create_account(@msafe_wallet);
        let payload = TEST_REGISTER_TX_PAYLOAD;
        validate_register_payload(payload, @msafe_wallet, @0xdead, 100)
    }

    #[test(aptos_framework = @aptos_framework)]
    #[expected_failure(abort_code = EMSAFE_TX_SENDER_INVALID)]
    fun test_check_register_payload_wrong_sender(
        aptos_framework: &signer
    ) {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        chain_id::initialize_for_test(aptos_framework, CHAIN_ID_FOR_TEST);
        aptos_account::create_account(@msafe_wallet);
        let payload = TEST_REGISTER_TX_PAYLOAD;
        validate_register_payload(payload, @0xdead, @test_msafe_module, 100)
    }

    #[test_only]
    fun init_creation_for_testing(msafe_address: address, owners: vector<address>, public_keys: vector<vector<u8>>) acquires PendingMultiSigCreations {
        let pending = borrow_global_mut<PendingMultiSigCreations>(THIS);
        table::add(&mut pending.creations, msafe_address, MomentumSafeCreation {
            owners,
            public_keys,
            nonce: 0,
            threshold: 2,
            txn: CreateWalletTxn {
                payload: TEST_REGISTER_TX_PAYLOAD,
                signatures: simple_map::create(),
            }
        })
    }

    #[test(
        msafe = @msafe,
        aptos_framework = @aptos_framework
    )]
    fun test_submit_signature(
        msafe: &signer,
        aptos_framework: &signer
    ) acquires PendingMultiSigCreations, MultiSigCreationEvent {
        init_test(msafe);
        timestamp::set_time_has_started_for_testing(aptos_framework);
        let msafe_address = @msafe_wallet;
        let public_key = OWNER_PUBLIC_KEY;
        init_creation_for_testing(msafe_address, vector::empty(), vector::singleton(public_key));
        submit_signature(msafe_address, 0, OWNER_REGISTER_TX_SIGNATURE);

        let pending = borrow_global<PendingMultiSigCreations>(THIS);
        let creation = table::borrow(&pending.creations, msafe_address);
        assert!(simple_map::contains_key(&creation.txn.signatures, &public_key), E)
    }

    #[test(
        msafe = @msafe,
        aptos_framework = @aptos_framework
    )]
    #[expected_failure(abort_code = ESIGNATURE_VERIFY_FAILED)]
    fun test_submit_invalid_signature(
        msafe: &signer,
        aptos_framework: &signer
    ) acquires PendingMultiSigCreations, MultiSigCreationEvent {
        init_test(msafe);
        timestamp::set_time_has_started_for_testing(aptos_framework);
        init_creation_for_testing(@msafe_wallet, vector::empty(), vector::singleton(OWNER_PUBLIC_KEY));
        submit_signature(@msafe_wallet, 0, SIGNATURE_INVALID);
    }

    #[test(msafe = @msafe)]
    #[expected_failure(abort_code = EMSAFE_NOT_FOUND)]
    fun test_get_creation_not_found(
        msafe: &signer,
    ) acquires PendingMultiSigCreations {
        init_test(msafe);
        get_creation(@0xa11cee);
    }
}

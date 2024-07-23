/// Momentum Safe core module.
///
/// For each created momentum safe wallet, it has resource `Momentum` registered
/// in this module, which stores information about:
///
///     1.  The information about the momentum safe wallet `Info`.
///     2.  Pending transaction, including payload, signatures, stored in `TxnBook`.
///
/// The information is stored per account to maximum performance by utilizing
/// parallel transaction processing in MOVE language.
///
/// This normal transaction execution works as follows:
///
///     1.  The momentum safe finishes the first signature collection in creator module
///         and call `momentum_safe::register`, where the momentum safe wallet information
///         and `TxnBook` used for storing information in pending transactions is
///         published within momentum_safe.
///     2.  Any of the owners of the momentum safe can initiate a transaction. The
///         type of transaction can contain any transaction payload, and the
///         transaction initiator encode the transaction payload and sign on
///         the payload off-chain.
///     3.  The transaction initiator submit the transaction payload and signatures on
///         chain via `momentum_safe::init_transaction`.
///     4.  The new transaction will be added to `Momentum.txn_book`, waiting for
///         signatures from other owners.
///
///     5.  The other owner keep track of `transaction_events` of their owned momentum
///         safes. Once a new transaction is observed, they may take actions on the
///         pending transaction.
///     6.  The other owner obtain the information about the pending transaction from
///         resource, and sign on the payload message.
///     7.  The other owner submit their signature on chain via
///         `momentum_safe.submit_signature`.
///     8.  The submitted signatue will be stored in `Transaction.signatures`.
///
///     9.  The last owner who approve the transaction gather the pending transaction
///         information from move resources, and sign on the transaction payload.
///     10. The last owner gathers the payload and signatures from blockchain, combining
///         with his own signature, and composes the multi-ed25519 signature.
///     11. The last owner execute the pending transaction with the momentum safe wallet
///         using multi-ed25519 signature from last step.
///
/// In some cases, user do not want to approve a certain transaction and expect to revert.
/// Momentum safe support this operation by the following process.
///
///     1.  Owner A initiate a transaction `tx1` with sequence number `sn`.
///     2.  Owner B do not want to execute `tx1`, and initiate another transaction `tx2`
///         with an empty payload with the same sequence number `sn`.
///     3.  Other owners can submit their signatures to `tx1` or `tx2`, or both.
///     4.  Eventually, either `tx1` or `tx2` will collect enough signatures and can
///         be executed.
///     5.  Since `tx1` and `tx2` have the same sequence number, executing one transaction
///         will immediately make another transaction invalid. Either `tx1` or `tx2` can
///         be executed depending on which transaction first collect enough signatures
///         and being executed.
///
/// Multiple pending transactions:
///
///     1.  There can be multiple pending transactions stored in a momentum safe wallet.
///     2.  The pending transactions will have incrementing sequence number, and all of
///         the pending transaction information is stored in struct `TxnBook`.
///     3.  The pending transactions need to be executed in sequence according to its
///         sequence number in the transaction payload.
///
module msafe::momentum_safe {
    use std::hash;
    use std::signer;
    use std::vector;
    use std::string::String;

    use aptos_framework::account;
    use aptos_framework::chain_id;
    use aptos_framework::multisig_account;
    use aptos_std::event::{Self, EventHandle};
    use aptos_std::simple_map::{Self, SimpleMap};
    use aptos_std::table_with_length::{Self, TableWithLength};

    use msafe::creator;
    use msafe::registry;
    use msafe::transaction;
    use msafe::utils;
    use msafe::migration;

    #[test_only]
    use aptos_framework::timestamp;

    // Error code

    /// Signature verify failed.
    const ESIGNATURE_VERIFY_FAILED: u64 = 1;

    /// Sequence number of the transaction is invalid.
    const EMSAFE_TX_SEQUENCE_NUMBER_INVALID: u64 = 2;

    /// Sender of transaction must be momentum safe address.
    const EMSAFE_TX_SENDER_INVALID: u64 = 3;

    /// The transaction is already expired.
    const EMSAFE_TX_EXPIRED: u64 = 4;
    /// Chain ID of transaction is invalid
    const EMSAFE_TX_CHAINID_INVALID: u64 = 5;
    /// MSafe has been migrated to 2.0
    const EMIGRATED: u64 = 6;
    const EMSAFE_SENDER_NOT_OWNER: u64 = 7;

    /// Limit of tx prune
    const MAX_PRUNE_ONCE: u8 = 128;

    /// Data structure stored for each momentum safe wallet, including:
    ///     1. momentum safe info (owners, public keys, threshold, e.t.c.)
    ///     2. TxnBook of pending transactions.
    struct Momentum has key {
        info: Info,
        txn_book: TxnBook,
    }

    /// Basic information of multi-sig wallet.
    /// Including owners, public keys, threshold, and wallet name (as metadata).
    struct Info has store, copy, drop {
        // vector of owners
        owners: vector<address>,
        // vector of public_keys that matches owners
        public_keys: vector<vector<u8>>,
        // creation nonce of the momentum safe
        nonce: u64,
        // signing threshold
        threshold: u8,
        // metadata for wallet information
        metadata: vector<u8>,
    }

    /// Stores the pending transactions of a multi-sig wallet.
    struct TxnBook has store {
        // Minimum sequence_number in the txn_book.
        // The parameter is updated and used in stale transaction pruning.
        min_sequence_number: u64,
        // Maximum sequence_number in the txn_book.
        // This parameter is updated when adding new transaction,
        // and is used in stale transaction pruning.
        max_sequence_number: u64,
        // A map from sequence number to the list of transactions hashes.
        // There can be multiple transaction with the same sequence number
        // in case there are conflicting transactions (E.g. revert transactions).
        // Eventually, only one of the transaction of the same sequence number
        // can be executed.
        // Note that the transaction hash here is different from of transaction
        // hash that is finalized in blockchain. It is a hash of the transaction
        // payload as a temporary identifier to the unique pending transactions.
        tx_hashes: TableWithLength<u64, vector<vector<u8>>>,
        // A map from transaction payload hash to the Transaction information.
        // Storing the detailed information about the pending transaction, where
        // the index transaction hashes can be obtained from `tx_hashes`.
        pendings: TableWithLength<vector<u8>, Transaction>,
    }

    /// Transaction includes all information needed for a certain transaction
    /// to be executed by the momentum safe wallet, including payload, metadata,
    /// and signatures.
    /// Initially, transaction will have only 1 signature. The signatures are
    /// added when other owners call addSignature. The transaction is ready to
    /// be sent when number of signatures reaches threshold - 1.
    struct Transaction has store, drop, copy {
        // Payload of the transaction to be executed by the momentum safe wallet.
        // Can be an arbitrary transaction payload.
        payload: vector<u8>,
        // Metadata stored on chain to serve as a transaction identifier or memo.
        metadata: vector<u8>,
        // Signatures collected so far. A map from public key to its corresponding
        // signature.
        signatures: SimpleMap<vector<u8>, vector<u8>>,
    }

    /// Event handlers for momentum safe. Two events are watched:
    ///     1. `momentum_safe.register`
    ///     2. `init_transaction`
    struct MomentumSafeEvent has key {
        register_events: EventHandle<Info>,
        transaction_events: EventHandle<Transaction>
    }

    /// Register the momentum safe wallet.
    ///
    /// This shall be the first transaction sent by the momentum safe wallet.
    /// The transaction is composed and enough number of signatures are collected
    /// asynchronizely from the creator module. The information about the momentum
    /// safe is also read from friend creator module.
    ///
    /// Publish the resource of the momentum safe wallet, remove the wallet
    /// creation data from creator, and move the registry data from pendings
    /// to created msafes for each owner.
    ///
    /// # Parameters
    /// * `msafe`: signer object of the momentum safe multi-sig wallet.
    /// * `metadata`: wallet name / URI / json data.
    ///
    /// # Aborts
    /// * `creator::EMSAFE_NOT_FOUND`: msafe address is not found in creator.
    /// * `registry::EADDRESS_NOT_REGISTRERED`: address is not registered at registry.
    /// * `registry::EMSAFE_NOT_REGISTERED`: momentum safe is not registered in pendings
    ///         under the owner resource.
    ///
    /// # Emits
    /// * `register_events`
    public entry fun register(
        msafe: &signer,
        metadata: vector<u8>
    ) {
        let msafe_address = signer::address_of(msafe);
        // HACK: Avoid web wallet throw an error during transaction simulation.
        // Momentum safe account is created in account.move at the call
        // `creator::init_wallet_creation`. However, a signature on this transaction
        // from wallet creation initiator is needed before calling
        // `creator::init_wallet_creation`. Thus add this temporary hack to allow
        // user to sign on register transaction.
        if (!account::exists_at(msafe_address)) {
            return
        };

        // Collect the momentum safe information from creator module, and then register
        // to `momentum_safe.Momentum`.
        let (owners, public_keys, nonce, threshold) = creator::get_creation(msafe_address);
        create_momentum(msafe, owners, public_keys, nonce, threshold, metadata);

        // After successful registration, clean and maintain dirty data in creator and
        // registry module.
        creator::remove_wallet_creation(msafe_address);
        add_to_registry(owners, msafe_address)
    }

    /// Initiate a new pending transaction. The new transaction data will be validated
    /// and write to `Momentum.TxnBook`.
    ///
    /// # Parameters
    /// * `msafe_address`: momentum safe address.
    /// * `pk_index`: index of the address in msafe owners.
    /// * `payload`: transaction payload to be executed.
    /// * `signature`: signature of the initiator.
    ///
    /// # Aborts
    /// * `ESIGNATURE_VERIFY_FAILED`: failed to verify signature.
    /// * `EMSAFE_TX_SENDER_INVALID`: Sender does not match msafe_address.
    /// * `EMSAFE_TX_SEQUENCE_NUMBER_INVALID`: Stale sequence number.
    /// * `EMSAFE_TX_EXPIRED`: Transaction has already expired in time.
    ///
    /// # Emits
    /// * `transaction_events`
    public entry fun init_transaction(
        msafe_address: address,
        pk_index: u8,
        payload: vector<u8>,
        signature: vector<u8>,
    ) acquires Momentum, MomentumSafeEvent {
        // Validate the transaction payload
        let (tx_sn, cur_sn) = validate_txn_payload(msafe_address, payload);
        init_transaction_internal(
            msafe_address,
            pk_index,
            payload,
            signature,
            tx_sn,
            cur_sn,
        )
    }

    fun init_transaction_internal(
        msafe_address: address,
        pk_index: u8,
        payload: vector<u8>,
        signature: vector<u8>,
        transaction_sn: u64,
        account_sn: u64,
    ) acquires Momentum, MomentumSafeEvent {
        // Add the transaction data to Momentum.TxnBook
        let momentum = borrow_global_mut<Momentum>(msafe_address);
        assert!(!is_migrated(momentum), EMIGRATED);
        let public_key = *vector::borrow(&momentum.info.public_keys, (pk_index as u64));
        let new_tx = Transaction {
            payload,
            metadata: vector::empty(),
            signatures: simple_map::create(),
        };
        add_signature(&mut new_tx, public_key, signature);
        add_to_txn_book(&mut momentum.txn_book, transaction_sn, new_tx);

        // Prune previous transactions with stale sequence number
        try_prune_pre_txs(&mut momentum.txn_book, account_sn - 1);

        // Emit the transaction event.
        let event_handle = borrow_global_mut<MomentumSafeEvent>(msafe_address);
        event::emit_event(
            &mut event_handle.transaction_events,
            move new_tx
        )
    }

    /// Submit the signature of a transaction.
    ///
    /// # Parameters
    /// * `msafe_address`: momentum safe wallet address.
    /// * `pk_index`: index of the owner.
    /// * `tx_hash`: hash of the transaction payload to be executed.
    /// * `signature`: signature on transaction payload.
    ///
    /// # Aborts
    /// * `ESIGNATURE_VERIFY_FAILED`: failed to verify signature.
    ///
    /// # Emits
    /// * `transaction event`
    public entry fun submit_signature(
        msafe_address: address,
        pk_index: u8,
        tx_hash: vector<u8>,
        signature: vector<u8>
    ) acquires Momentum, MomentumSafeEvent {
        // add the signature to `Transaction`
        let momentum = borrow_global_mut<Momentum>(msafe_address);
        let public_key = *vector::borrow(&momentum.info.public_keys, (pk_index as u64));
        let tx = table_with_length::borrow_mut(&mut momentum.txn_book.pendings, tx_hash);
        add_signature(tx, public_key, signature);

        // emit an event.
        let event_handle = borrow_global_mut<MomentumSafeEvent>(msafe_address);
        event::emit_event(
            &mut event_handle.transaction_events,
            *tx
        )
    }

    /// Literally do nothing :)
    /// Used as an empty transaction payload to revert a transaction.
    public entry fun do_nothing() {}

    /// Validate the transaction payload.
    ///
    /// # Parameters
    /// * `msafe_address`: momentum safe address.
    /// * `payload`: transaction payload to be verified.
    ///
    /// # Returns
    /// * `u64`: sequence number deserialized from payload.
    /// * `u64`: momentum safe's current sequence number.
    ///
    /// # Aborts
    /// * `EMSAFE_TX_SENDER_INVALID`: Sender does not match msafe_address.
    /// * `EMSAFE_TX_SEQUENCE_NUMBER_INVALID`: Stale sequence number.
    /// * `EMSAFE_TX_EXPIRED`: Transaction has already expired in time.
    fun validate_txn_payload(
        msafe_address: address,
        payload: vector<u8>,
    ): (
        u64,
        u64,
    ) {
        let txn = transaction::decode_transaction(payload);

        let sender = transaction::get_sender(&txn);
        assert!(sender == msafe_address, EMSAFE_TX_SENDER_INVALID);

        let tx_chain_id = transaction::get_chain_id(&txn);
        assert!(tx_chain_id == chain_id::get(), EMSAFE_TX_CHAINID_INVALID);

        let tx_sn = transaction::get_sequence_number(&txn);
        let cur_sn = account::get_sequence_number(msafe_address);
        assert!(cur_sn <= tx_sn, EMSAFE_TX_SEQUENCE_NUMBER_INVALID);

        let expire = transaction::get_expiration_timestamp_secs(&txn);
        assert!(expire > utils::now_seconds(), EMSAFE_TX_EXPIRED);

        (tx_sn, cur_sn)
    }

    /// Verifies and add the signature to Transaction.
    ///
    /// # Parameters
    /// * `tx`: mutable reference to Transaction data.
    /// * `public_key`: public key of the signer.
    /// * `signature`: signature to be verified and added.
    ///
    /// # Aborts
    /// * `ESIGNATURE_VERIFY_FAILED`: signature fails the verification.
    fun add_signature(
        tx: &mut Transaction,
        public_key: vector<u8>,
        signature: vector<u8>
    ) {
        verify_signature(signature, public_key, tx.payload);
        simple_map::add(&mut tx.signatures, public_key, signature);
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

    /// Move the momentum safe addresses from `pendings` to `msafes` in registry data
    /// when momentum safe is successfully registered.
    ///
    /// # Parameters
    /// * `owners`: owner address vector.
    /// * `msafe_address`: address of momentum safe wallet.
    ///
    /// # Emits
    /// * `RegisterEvent`
    fun add_to_registry(
        owners: vector<address>,
        msafe_address: address
    ) {
        registry::register_msafe(&owners, msafe_address, false)
    }

    /// Create and publish the data at momentum_safe. Called by register function.
    ///
    /// # Parameters
    /// * `msafe`: signer object of the momentum safe.
    /// * `owners`: owner address vector.
    /// * `public_keys`: owner public keys.
    /// * `nonce`: creation nonce.
    /// * `threshold`: signing threshold.
    /// * `metadata`: wallet information.
    ///
    /// # Emits
    /// * `register_events`
    fun create_momentum(
        msafe: &signer,
        owners: vector<address>,
        public_keys: vector<vector<u8>>,
        nonce: u64,
        threshold: u8,
        metadata: vector<u8>
    ) {
        let info = Info {
            owners,
            public_keys,
            nonce,
            threshold,
            metadata,
        };
        let init_sequence_number = account::get_sequence_number(signer::address_of(msafe));
        move_to(msafe, Momentum {
            info,
            txn_book: TxnBook {
                min_sequence_number: init_sequence_number,
                max_sequence_number: init_sequence_number,
                tx_hashes: table_with_length::new(),
                pendings: table_with_length::new(),
            },
        });
        let register_events = account::new_event_handle<Info>(msafe);
        event::emit_event(&mut register_events, move info);
        move_to(msafe, MomentumSafeEvent {
            register_events,
            transaction_events: account::new_event_handle(msafe)
        });
    }

    /// Prune the pending transactions with sequence number from
    /// `txn_book.min_sequence_number` to `end_sequence_number`. The function is
    /// called when initiating a new transaction to clean stale transactions.
    ///
    /// # Parameters
    /// * `txn_book`: mutable reference to the txn_book. Prune transactions within
    ///         txn_book.
    /// * `end_sequence_number`: Prune until the end_sequence_number.
    fun try_prune_pre_txs(
        txn_book: &mut TxnBook,
        end_sequence_number: u64
    ) {
        let start = txn_book.min_sequence_number;
        let prune_remain = MAX_PRUNE_ONCE;

        while (start <= end_sequence_number && prune_remain > 0) {
            let (remain, dirty) = prune_txs_at(txn_book, start, prune_remain);
            prune_remain = remain;
            if (dirty) {
                break
            };
            start = start + 1;
        };
        txn_book.min_sequence_number = start;
    }

    /// Prune transactions from `txn_book` at the given sequence number.
    ///
    /// # Parameters
    /// * `txn_book`: Prune the transaction within mutable txn_book.
    /// * `tx_sn`: Target sequence number to prune.
    /// * `remain_limit`: remain prune limit
    ///
    /// # Returns
    /// * `u8`: remain prune limit after prune
    /// * `bool`: true means transactions are pruned is still dirty
    fun prune_txs_at(
        txn_book: &mut TxnBook,
        tx_sn: u64,
        remain_limit: u8
    ): (u8, bool) {
        if (table_with_length::contains(&txn_book.tx_hashes, tx_sn)) {
            let tx_hashes = table_with_length::remove(&mut txn_book.tx_hashes, tx_sn);
            while (!vector::is_empty(&tx_hashes) && remain_limit > 0) {
                remain_limit = remain_limit - 1;
                let tx_hash = vector::pop_back(&mut tx_hashes);
                table_with_length::remove(&mut txn_book.pendings, tx_hash);
            };
            if (!vector::is_empty(&tx_hashes)) {
                table_with_length::add(&mut txn_book.tx_hashes, tx_sn, tx_hashes);
                return (remain_limit, true)
            }
        };
        (remain_limit, false)
    }

    /// Add the transaction to `txn_book`.
    ///
    /// # Parameters
    /// * `txn_book`: New transaction is added to mutable txn_book.
    /// * `tx_sequence_number`: Transaction sequence number.
    /// * `tx`: Transaction structure.
    ///
    /// # Aborts
    /// * `EMSAFE_TX_SEQUENCE_NUMBER_INVALID`: transaction sequence number is more than 1
    ///         greater than `max_sequence_number`.
    fun add_to_txn_book(
        txn_book: &mut TxnBook,
        tx_sequence_number: u64,
        tx: Transaction
    ) {
        // Sequence number arithmetic. Only accept max_sequence_number + 1
        if (tx_sequence_number > txn_book.max_sequence_number) {
            txn_book.max_sequence_number = txn_book.max_sequence_number + 1;
        };
        assert!(tx_sequence_number <= txn_book.max_sequence_number, EMSAFE_TX_SEQUENCE_NUMBER_INVALID);

        // transaction id is the hash of the payload.
        let tx_id = hash::sha3_256(tx.payload);

        // Add transaction to txn_book.
        table_with_length::add(&mut txn_book.pendings, tx_id, move tx);
        if (!table_with_length::contains(&txn_book.tx_hashes, tx_sequence_number)) {
            table_with_length::add(&mut txn_book.tx_hashes, tx_sequence_number, vector::empty())
        };
        let nonce_txs = table_with_length::borrow_mut(&mut txn_book.tx_hashes, tx_sequence_number);
        vector::push_back(nonce_txs, tx_id);
    }

    struct MigrationEvent has store,drop {
        msafe_address: address,
        info: Info,
        metadatas: SimpleMap<String, vector<u8>>,
    }

    struct Migration has key {
        event: EventHandle<MigrationEvent>
    }

    public entry fun enable_migration(deployer: &signer) {
        assert!(signer::address_of(deployer) == @msafe, EMSAFE_SENDER_NOT_OWNER);
        move_to(deployer, Migration {
            event: account::new_event_handle(deployer)
        });
    }

    /// Initiate a new pending migration message. The new migration message data will be validated
    /// and write to `Momentum.TxnBook`.
    ///
    /// # Parameters
    /// * `msafe_address`: momentum safe address.
    /// * `pk_index`: index of the address in msafe owners.
    /// * `sequence_number`: sequence number of the migration message.
    /// * `signature`: signature of the migration message.
    public entry fun init_migration(
        msafe_address: address,
        pk_index: u8,
        sequence_number: u64,
        signature: vector<u8>
    ) acquires Momentum, MomentumSafeEvent {
        let cur_sn = account::get_sequence_number(msafe_address);
        assert!(cur_sn <= sequence_number, EMSAFE_TX_SEQUENCE_NUMBER_INVALID);
        let momentum = borrow_global_mut<Momentum>(msafe_address);
        let payload = migration::build_proof_challenge(
            msafe_address,
            sequence_number,
            momentum.info.owners,
            momentum.info.threshold
        );
        init_transaction_internal(msafe_address, pk_index, payload, signature, sequence_number, cur_sn)
    }

    const MULTI_ED25519_SCHEME: u8 = 1;
    const MAX_U64: u64 = 0xffffffffffffffff;

    /// Complete the migration. It will mark the multisig account to migrated and call system api
    /// to complete the migration.
    ///
    /// # Parameters
    /// * `msafe_address`: momentum safe address to be migrated.
    /// * `account_public_key`: public keys of the multisig account.
    /// * `create_multisig_account_signed_message`: merged signatures of migration message.
    /// * `metadata_keys`: metadata keys of the multisig account.
    /// * `metadata_values`: metadata values of the multisig account.
    public entry fun migrate(
        msafe_address: address,
        account_public_key: vector<u8>,
        create_multisig_account_signed_message: vector<u8>,
        metadata_keys: vector<String>,
        metadata_values: vector<vector<u8>>,
    ) acquires Momentum,Migration {
        let momentum = borrow_global_mut<Momentum>(msafe_address);
        // 1. mark Momentum of multisig_address to migrated
        mark_migrated(momentum);
        // 2. mark msafe in OwnerMomentumSafes.msafes to migrated
        registry::mark_migrated(&momentum.info.owners, msafe_address);
        // 3. call system api to complete migration
        multisig_account::create_with_existing_account_and_revoke_auth_key(
            msafe_address,
            momentum.info.owners,
            (momentum.info.threshold as u64),
            MULTI_ED25519_SCHEME,
            account_public_key,
            create_multisig_account_signed_message,
            metadata_keys,
            metadata_values,
        );

        let migration = borrow_global_mut<Migration>(@msafe);
        event::emit_event(&mut migration.event, MigrationEvent{
            msafe_address,
            info: momentum.info,
            metadatas: simple_map::new_from(metadata_keys, metadata_values),
        })
    }

    fun mark_migrated(momentum: &mut Momentum) {
        momentum.txn_book.min_sequence_number = MAX_U64;
    }

    fun is_migrated(momentum: &Momentum): bool {
        momentum.txn_book.min_sequence_number == MAX_U64
    }

    #[view]
    /// Get the status of the Momentum safes.
    ///
    /// # Parameters
    /// * `msafe_address_vec`: vector of Momentum safe addresses.
    /// # Returns
    /// * `vector<u8>`: vector of status of Momentum safes. 0 for normal, 1 for migrating, 2 for migrated.
    public fun msafe_vec_status(msafe_address_vec: vector<address>): vector<u8> acquires Momentum {
        let results = vector::empty<u8>();
        let i = 0;
        while (i < vector::length(&msafe_address_vec)) {
            let msafe_address = *vector::borrow(&msafe_address_vec, i);
            let status = msafe_status(msafe_address);
            vector::push_back(&mut results, status);
            i = i + 1;
        };
        results
    }

    const MSAFE_NORMAL:u8 = 0;
    const MSAFE_MIGRATING:u8 = 1;
    const MSAFE_MIGRATED:u8 = 2;

    #[view]
    /// Get the status of the Momentum safe.
    ///
    /// # Parameters
    /// * `msafe_address`: Momentum safe addresses.
    /// # Returns
    /// * `u8`: status of Momentum safes. 0 for normal, 1 for migrating, 2 for migrated.
    public fun msafe_status(msafe_address: address):u8 acquires Momentum {
        let momentum = borrow_global<Momentum>(msafe_address);
        if(is_migrated(momentum)) {
            return MSAFE_MIGRATED
        };
        let start_sn = account::get_sequence_number(msafe_address);
        while(start_sn <= momentum.txn_book.max_sequence_number) {
            let hashes =table_with_length::borrow(&momentum.txn_book.tx_hashes, start_sn);
            let i = 0;
            while(i < vector::length(hashes)) {
                let tx_hash = *vector::borrow(hashes, i);
                let tx =   table_with_length::borrow(&momentum.txn_book.pendings, tx_hash);
                if(migration::is_proof_challenge(tx.payload)) {
                    return MSAFE_MIGRATING
                };
                i = i + 1;
            };
            start_sn = start_sn + 1;
        };
        MSAFE_NORMAL
    }


    #[test_only]
    const E: u64 = 0;

    #[test_only]
    const TEST_REGISTER_TX_PAYLOAD: vector<u8> = x"b5e97db07fa0bd0e5598aa3643a9bc6f6693bddc1a9fec9e674a461eaa00b193c0455c582b0e3d794918db7de1f1c218ac311701db218958718e74494703fd3b0000000000000000024cebef114d8ce88cc1e1df73b9a6effa51bf58105b18e2be2dc222c84a3e54850d6d6f6d656e74756d5f7361666508726567697374657200010d0c68656c6c6f206d2d73616665d0070000000000000100000000000000d0e22663000000001f";

    #[test_only]
    const OWNER_PUBLIC_KEY: vector<u8> = x"fb2c62d2ab98f1e6454a83ec0b7a2102a3d6b84d6c6d89ec013ba544f823345a";

    #[test_only]
    const OWNER_REGISTER_TX_SIGNATURE: vector<u8> = x"40e66eda2884c6e9cb639dcc4b4c85d45a98583b1ad37c1a3df52be23a6b22cf20647eb4c9ac03469ef3c5567f021e5b032e8fd0d0a5b9f1faae23ee9b1eea01";

    #[test_only]
    const TEST_INIT_TX_PAYLOAD: vector<u8> = x"b5e97db07fa0bd0e5598aa3643a9bc6f6693bddc1a9fec9e674a461eaa00b193c0455c582b0e3d794918db7de1f1c218ac311701db218958718e74494703fd3b010000000000000002000000000000000000000000000000000000000000000000000000000000000104636f696e087472616e73666572010700000000000000000000000000000000000000000000000000000000000000010a6170746f735f636f696e094170746f73436f696e00022060b3de55bd7f07bd5cd22426d07a9bd3143546700e329e72731b387d78ce92ad08e803000000000000d0070000000000000100000000000000e4e22663000000001f";

    #[test_only]
    const OWNER_INIT_TX_SIGNATURE: vector<u8> = x"e0612871f821d6bf4ca0364b5aae3131528f1bd7f33b5782084698975d3555c519dc9a9a6a2c5e97c6b00fe0b49c61f4dbe1dce133b83983edd37caf0f1aee0d";

    #[test_only]
    const SIGNATURE_INVALID: vector<u8> = x"1111b0a36be89cec78f710bd139620bae9c5ea3b003641a98a079f38fea73b66bb830df49ff1df9cbc9d268d412ad08324e2401ef8cf008b7c4abf097b284203";

    #[test]
    public entry fun test_add_signature() {
        let payload = TEST_REGISTER_TX_PAYLOAD;
        let signature = OWNER_REGISTER_TX_SIGNATURE;
        let public_key = OWNER_PUBLIC_KEY;
        let txn = Transaction {
            payload,
            metadata: b"hello msafe",
            signatures: simple_map::create()
        };
        add_signature(&mut txn, public_key, signature);
        assert!(simple_map::contains_key(&txn.signatures, &public_key), E)
    }

    #[test]
    #[expected_failure]
    public entry fun test_add_invalid_signature() {
        let payload = TEST_REGISTER_TX_PAYLOAD;
        let signature_invalid = SIGNATURE_INVALID;
        let public_key = OWNER_PUBLIC_KEY;
        let txn = Transaction {
            payload,
            metadata: b"hello msafe",
            signatures: simple_map::create()
        };
        add_signature(&mut txn, public_key, signature_invalid);
    }

    #[test_only]
    fun generate_testing_txn_book(storage: &signer, sn_num: u8, tx_per_sn: u8) {
        let txn_book = TxnBook {
            min_sequence_number: 0,
            max_sequence_number: 0,
            tx_hashes: table_with_length::new(),
            pendings: table_with_length::new(),
        };
        let i = 0u8;
        while (i < sn_num) {
            let tx_sequence_number = txn_book.min_sequence_number + (i as u64);
            let j = 0u8;
            while (j < tx_per_sn) {
                add_to_txn_book(&mut txn_book, tx_sequence_number, Transaction {
                    payload: vector::singleton<u8>(i * tx_per_sn + j),
                    metadata: b"test",
                    signatures: simple_map::create(),
                });
                j = j + 1
            };
            i = i + 1
        };
        // we have to store txn_book into somewhere, because it can't have 'drop' ability.
        move_to(storage, Momentum {
            info: Info {
                owners: vector::empty(),
                public_keys: vector::empty(),
                nonce: 0,
                threshold: 0,
                metadata: vector::empty()
            },
            txn_book
        })
    }

    #[test(storage = @0xdead)]
    public entry fun test_try_prune_pre_txs(storage: &signer) acquires Momentum {
        generate_testing_txn_book(storage, 5, 2);
        let momentum = borrow_global_mut<Momentum>(signer::address_of(storage));
        let txn_book = &mut momentum.txn_book;
        let max_sequence_number = txn_book.max_sequence_number;
        try_prune_pre_txs(txn_book, max_sequence_number);
        assert!(txn_book.min_sequence_number == txn_book.max_sequence_number + 1, E);
        assert!(table_with_length::length(&txn_book.pendings) == 0, E);
        assert!(table_with_length::length(&txn_book.tx_hashes) == 0, E);
    }

    #[test(storage = @0xdead)]
    public entry fun test_try_prune_pre_txs_limit(storage: &signer) acquires Momentum {
        let tx_per_sn = 4;
        generate_testing_txn_book(storage, MAX_PRUNE_ONCE / (tx_per_sn - 1), tx_per_sn);
        let momentum = borrow_global_mut<Momentum>(signer::address_of(storage));
        let txn_book = &mut momentum.txn_book;
        let total_txs = table_with_length::length(&txn_book.pendings);
        let max_sequence_number = txn_book.max_sequence_number;
        try_prune_pre_txs(txn_book, max_sequence_number);
        assert!(txn_book.min_sequence_number == ((MAX_PRUNE_ONCE + tx_per_sn - 1) / tx_per_sn as u64), E);
        assert!(table_with_length::length(&txn_book.pendings) == total_txs - (MAX_PRUNE_ONCE as u64), E);
        try_prune_pre_txs(txn_book, max_sequence_number);
        assert!(txn_book.min_sequence_number == txn_book.max_sequence_number + 1, E);
        assert!(table_with_length::length(&txn_book.pendings) == 0, E);
        assert!(table_with_length::length(&txn_book.tx_hashes) == 0, E);
    }

    #[test(aptos_framework = @aptos_framework)]
    fun test_init_transaction(aptos_framework: &signer) acquires Momentum, MomentumSafeEvent {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        chain_id::initialize_for_test(aptos_framework, 31);
        let msafe_address = @msafe_wallet;
        let msafe_wallet = &account::create_account_for_test(msafe_address);
        // first transaction of msafe is momentum_safe::register(...), so sn of init transaction should >= 1.
        account::increment_sequence_number_for_test(msafe_address);
        let payload = TEST_INIT_TX_PAYLOAD;
        let signature = OWNER_INIT_TX_SIGNATURE;
        let public_key = OWNER_PUBLIC_KEY;
        create_momentum(msafe_wallet, vector::empty(), vector::singleton(public_key), 0, 2, b"hello msafe");
        init_transaction(msafe_address, 0, payload, signature);
    }

    #[test]
    fun test_submit_signature() acquires Momentum, MomentumSafeEvent {
        let msafe_address = @msafe_wallet;
        let msafe_wallet = &account::create_account_for_test(msafe_address);
        let payload = TEST_REGISTER_TX_PAYLOAD;
        let signature = OWNER_REGISTER_TX_SIGNATURE;
        let public_key = OWNER_PUBLIC_KEY;
        create_momentum(
            msafe_wallet,
            vector::empty(),
            vector::singleton(public_key),
            0,
            2,
            b"hello msafe"
        );

        let txn_book = &mut borrow_global_mut<Momentum>(msafe_address).txn_book;
        add_to_txn_book(txn_book, 0, Transaction {
            payload,
            metadata: b"test",
            signatures: simple_map::create(),
        });
        let tx_id = hash::sha3_256(payload);
        submit_signature(signer::address_of(msafe_wallet), 0, tx_id, signature);
        let momentum = borrow_global_mut<Momentum>(msafe_address);
        let tx = table_with_length::borrow(&momentum.txn_book.pendings, tx_id);
        assert!(simple_map::contains_key(&tx.signatures, &public_key), E);
    }

    #[test]
    #[expected_failure]
    fun test_submit_invalid_signature() acquires Momentum, MomentumSafeEvent {
        let msafe_address = @msafe_wallet;
        let msafe_wallet = &account::create_account_for_test(msafe_address);
        let payload = TEST_REGISTER_TX_PAYLOAD;
        let signature_invalid = SIGNATURE_INVALID;
        let public_key = OWNER_PUBLIC_KEY;
        create_momentum(
            msafe_wallet,
            vector::empty(),
            vector::singleton(public_key),
            0,
            2,
            b"hello msafe"
        );

        let txn_book = &mut borrow_global_mut<Momentum>(msafe_address).txn_book;
        add_to_txn_book(txn_book, 0, Transaction {
            payload,
            metadata: b"test",
            signatures: simple_map::create(),
        });
        let tx_id = hash::sha3_256(payload);
        submit_signature(signer::address_of(msafe_wallet), 0, tx_id, signature_invalid);
        let momentum = borrow_global_mut<Momentum>(msafe_address);
        let tx = table_with_length::borrow(&momentum.txn_book.pendings, tx_id);
        assert!(simple_map::contains_key(&tx.signatures, &public_key), E);
    }
}
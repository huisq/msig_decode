module msafe::migration {
    use aptos_std::type_info::{Self, TypeInfo};
    use aptos_framework::multisig_account;
    use aptos_framework::chain_id;
    use std::bcs;
    #[test_only]
    use std::features;
    #[test_only]
    use aptos_framework::timestamp;
    #[test_only]
    use std::string;
    #[test_only]
    use aptos_std::simple_map;
    #[test_only]
    use aptos_framework::account;
    use msafe::utils;

    friend msafe::momentum_safe;

    /// Signature verify failed.
    const ESIGNATURE_VERIFY_FAILED: u64 = 1;

    /// forked from `aptos_framework::mulgisig_account::MultisigAccountCreationWithAuthKeyRevocationMessage`
    struct MultisigAccountCreationWithAuthKeyRevocationMessage has copy, drop {
        // Chain id is included to prevent cross-chain replay.
        chain_id: u8,
        // Account address is included to prevent cross-account replay (when multiple accounts share the same auth key).
        account_address: address,
        // Sequence number is not needed for replay protection as the multisig account can only be created once.
        // But it's included to ensure timely execution of account creation.
        sequence_number: u64,
        // The list of owners for the multisig account.
        owners: vector<address>,
        // The number of signatures required (signature threshold).
        num_signatures_required: u64,
    }

    struct MultisigAccountCreationMessage has copy, drop {
        // Chain id is included to prevent cross-chain replay.
        chain_id: u8,
        // Account address is included to prevent cross-account replay (when multiple accounts share the same auth key).
        account_address: address,
        // Sequence number is not needed for replay protection as the multisig account can only be created once.
        // But it's included to ensure timely execution of account creation.
        sequence_number: u64,
        // The list of owners for the multisig account.
        owners: vector<address>,
        // The number of signatures required (signature threshold).
        num_signatures_required: u64,
    }

    /// forked from `aptos_std::ed25519::SignedMessage`
    struct SignedMessage has drop {
        type_info: TypeInfo,
        inner: MultisigAccountCreationMessage,
    }

    public fun build_proof_challenge(msafe: address, sequence_number: u64, owners: vector<address>, threshold: u8): vector<u8> {
        let signed_message = SignedMessage {
            type_info: type_info::type_of<multisig_account::MultisigAccountCreationWithAuthKeyRevocationMessage>(),
            inner: MultisigAccountCreationMessage {
                chain_id: chain_id::get(),
                account_address: msafe,
                sequence_number,
                owners,
                num_signatures_required: (threshold as u64),
            }
        };
        bcs::to_bytes(&signed_message)
    }

    /// Weak check if the payload is a proof challenge.
    public fun is_proof_challenge(payload: vector<u8>): bool {
        let info = type_info::type_of<multisig_account::MultisigAccountCreationWithAuthKeyRevocationMessage>();
        utils::starts_with(payload, bcs::to_bytes(&info))
    }

    #[test_only]
    const TEST_CHAIN_ID: u8 = 1;
    #[test_only]
    const ZERO_AUTHKEY: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fun test_migrate() {
        setup();
        let multisig_address = @0x0b9a759ba38089214926b6233947d1b359605e4c68a8786ae252f95ac4f1798c;
        let sequence_number = 12u64;
        let expected_owners = vector[
            @0xcbf7c6ad2adc9c85a98ec416aac48ac6c9e92a7f337a2ca4794ca54afb0ed962,
            @0x359e54ad626d80e535c05474d46f2ac2e3967bc0114404310d710cf513bf4894
        ];
        let pubkeys = x"28c0d46c453525edcdafeed55e7f3e6b6ae3a0ec4aef8742442783c8c047e0d2bec3deee998a8ee44ec4715de2475bb6fa4e1765adacc8dab170b170e0f72898329d9bbe8f70aecbf84199870613fbdc0000000000000000000000000000000002";
        let signatures = x"33d2ad72c88201852eb82af37a93e83762a45b3e79231289a6fc2528a2771bbaca0f29f57f13712f0f3c23729a5814c0778633de3ad9b293fbc017577d54fb0b7d8655fab8f0ffcc2b8347b2712a7a64a2bc2f7a7b3d6a0e195e3acb4d843b23610aaa00a9ddaefb9d62c3695a646864fc1734cdfd39ca3cd243af6c9c9eb201c0000000";
        let num_signatures_required = 2u64;
        let proof_expect = x"0000000000000000000000000000000000000000000000000000000000000001106d756c74697369675f6163636f756e74334d756c74697369674163636f756e744372656174696f6e57697468417574684b65795265766f636174696f6e4d657373616765010b9a759ba38089214926b6233947d1b359605e4c68a8786ae252f95ac4f1798c0c0000000000000002cbf7c6ad2adc9c85a98ec416aac48ac6c9e92a7f337a2ca4794ca54afb0ed962359e54ad626d80e535c05474d46f2ac2e3967bc0114404310d710cf513bf48940200000000000000";
        let proof = build_proof_challenge(multisig_address, sequence_number, expected_owners, (num_signatures_required as u8));

        assert!(proof == proof_expect, 0);

        account::create_account_for_test(multisig_address);
        account::set_sequence_number(multisig_address, sequence_number);

        multisig_account::create_with_existing_account_and_revoke_auth_key(
            multisig_address,
            expected_owners,
            num_signatures_required,
            1, // MULTI_ED25519_SCHEME
            pubkeys,
            signatures,
            vector[string::utf8(b"MSafe")],
            vector[b"MSafe1.0"],
        );
        assert!(account::get_authentication_key(multisig_address) == ZERO_AUTHKEY, 0);
        assert!(multisig_account::owners(multisig_address) == expected_owners, 0);
        assert!(multisig_account::num_signatures_required(multisig_address) == num_signatures_required, 0);
        let metadata = multisig_account::metadata(multisig_address);
        assert!(*simple_map::borrow(&metadata, &string::utf8(b"MSafe")) == b"MSafe1.0", 0);
    }

    #[test_only]
    fun setup() {
        let framework_signer = &account::create_signer_for_test(@std);
        features::change_feature_flags(
            framework_signer, vector[features::get_multisig_accounts_feature()], vector[]);
        timestamp::set_time_has_started_for_testing(framework_signer);
        chain_id::initialize_for_test(framework_signer, TEST_CHAIN_ID);
    }
}
module 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::migration {
    struct MultisigAccountCreationWithAuthKeyRevocationMessage has copy, drop {
        chain_id: u8,
        account_address: address,
        sequence_number: u64,
        owners: vector<address>,
        num_signatures_required: u64,
    }
    
    struct SignedMessage has drop {
        type_info: 0x1::type_info::TypeInfo,
        inner: MultisigAccountCreationWithAuthKeyRevocationMessage,
    }
    
    public fun build_proof_challenge(arg0: address, arg1: u64, arg2: vector<address>, arg3: u8) : vector<u8> {
        let v0 = MultisigAccountCreationWithAuthKeyRevocationMessage{
            chain_id                : 0x1::chain_id::get(), 
            account_address         : arg0, 
            sequence_number         : arg1, 
            owners                  : arg2, 
            num_signatures_required : arg3 as u64,
        };
        let v1 = SignedMessage{
            type_info : 0x1::type_info::type_of<0x1::multisig_account::MultisigAccountCreationWithAuthKeyRevocationMessage>(), 
            inner     : v0,
        };
        0x1::bcs::to_bytes<SignedMessage>(&v1)
    }
    
    public fun is_proof_challenge(arg0: vector<u8>) : bool {
        let v0 = 0x1::type_info::type_of<0x1::multisig_account::MultisigAccountCreationWithAuthKeyRevocationMessage>();
        0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::utils::starts_with(arg0, 0x1::bcs::to_bytes<0x1::type_info::TypeInfo>(&v0))
    }
    
    // decompiled from Move bytecode v6
}


use connection_router::{Message, state::CrossChainId};
use cosmwasm_std::Addr;
use test_utils::Worker;

mod test_utils;

#[test]
fn worker_set_can_be_initialized_and_then_manually_updated() {
    let chains: Vec<connection_router::state::ChainName> = vec![
        "Ethereum".to_string().try_into().unwrap(),
        "Polygon".to_string().try_into().unwrap(),
    ];
    let (mut protocol, ethereum, _, initial_workers, min_worker_bond) =
        test_utils::setup_test_case();

    let simulated_worker_set = test_utils::workers_to_worker_set(&mut protocol, &initial_workers);

    let worker_set =
        test_utils::get_worker_set(&mut protocol.app, &ethereum.multisig_prover_address);

    assert_eq!(worker_set, simulated_worker_set);

    // add third and fourth worker
    let mut new_workers = Vec::new();
    let new_worker = Worker {
        addr: Addr::unchecked("worker3"),
        supported_chains: chains.clone(),
        key_pair: test_utils::generate_key(2),
    };
    new_workers.push(new_worker);
    let new_worker = Worker {
        addr: Addr::unchecked("worker4"),
        supported_chains: chains.clone(),
        key_pair: test_utils::generate_key(3),
    };
    new_workers.push(new_worker);

    let expected_new_worker_set = test_utils::workers_to_worker_set(&mut protocol, &new_workers);

    test_utils::register_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.multisig_address.clone(),
        protocol.governance_address.clone(),
        protocol.genesis_address.clone(),
        &new_workers,
        protocol.service_name.clone(),
        min_worker_bond,
    );

    // remove old workers
    test_utils::deregister_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.governance_address.clone(),
        &initial_workers,
        protocol.service_name.clone(),
    );

    let response = test_utils::update_worker_set(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        ethereum.multisig_prover_address.clone(),
    );

    // sign with old workers
    let session_id = test_utils::sign_proof(
        &mut protocol.app,
        &protocol.multisig_address,
        &initial_workers,
        response,
    );

    let proof = test_utils::get_proof(
        &mut protocol.app,
        &ethereum.multisig_prover_address,
        &session_id,
    );
    assert!(matches!(
        proof.status,
        multisig_prover::msg::ProofStatus::Completed { .. }
    ));

    assert_eq!(proof.message_ids.len(), 0);

    let (poll_id, expiry) = test_utils::create_worker_set_poll(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        ethereum.voting_verifier_address.clone(),
        expected_new_worker_set.clone(),
    );

    // do voting
    test_utils::vote_true_for_worker_set(
        &mut protocol.app,
        &ethereum.voting_verifier_address,
        &new_workers,
        poll_id,
    );

    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);

    test_utils::end_poll(
        &mut protocol.app,
        &ethereum.voting_verifier_address,
        poll_id,
    );

    test_utils::confirm_worker_set(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        ethereum.multisig_prover_address.clone(),
    );

    let new_worker_set =
        test_utils::get_worker_set(&mut protocol.app, &ethereum.multisig_prover_address);

    assert_eq!(new_worker_set, expected_new_worker_set);
}

#[test]
fn xrpl_worker_set_can_be_initialized_and_then_manually_updated() {
    let chains: Vec<connection_router::state::ChainName> = vec![
        "Ethereum".to_string().try_into().unwrap(),
        "XRPL".to_string().try_into().unwrap(),
    ];
    let (mut protocol, _, xrpl, initial_workers, min_worker_bond) =
        test_utils::setup_xrpl_destination_test_case();

    let simulated_worker_set = test_utils::xrpl_workers_to_worker_set(&mut protocol, &initial_workers);

    let worker_set =
        test_utils::get_xrpl_worker_set(&mut protocol.app, &xrpl.multisig_prover_address);

    assert_eq!(worker_set, simulated_worker_set);

    // add third and fourth worker
    let mut new_workers = Vec::new();
    let new_worker = Worker {
        addr: Addr::unchecked("worker3"),
        supported_chains: chains.clone(),
        key_pair: test_utils::generate_key(2),
    };
    new_workers.push(new_worker);
    let new_worker = Worker {
        addr: Addr::unchecked("worker4"),
        supported_chains: chains.clone(),
        key_pair: test_utils::generate_key(3),
    };
    new_workers.push(new_worker);

    let expected_new_worker_set = test_utils::xrpl_workers_to_worker_set(&mut protocol, &new_workers);

    test_utils::register_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.multisig_address.clone(),
        protocol.governance_address.clone(),
        protocol.genesis_address.clone(),
        &new_workers,
        protocol.service_name.clone(),
        min_worker_bond,
    );

    // remove old workers
    test_utils::deregister_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.governance_address.clone(),
        &initial_workers,
        protocol.service_name.clone(),
    );

    let session_id = test_utils::construct_xrpl_signer_list_set_proof_and_sign(
        &mut protocol.app,
        &xrpl.multisig_prover_address,
        &protocol.multisig_address,
        &initial_workers,
    );

    let proof = test_utils::get_xrpl_proof(
        &mut protocol.app,
        &xrpl.multisig_prover_address,
        &session_id,
    );
    assert!(matches!(
        proof,
        xrpl_multisig_prover::contract::GetProofResponse::Completed { .. }
    ));
    println!("SignerListSet proof: {:?}", proof);

    test_utils::finalize_xrpl_proof(
        &mut protocol.app,
        &xrpl.multisig_prover_address,
        &session_id,
    );

    let proof_msg_id = CrossChainId {
        chain: xrpl.chain_name.clone(),
        id: "3387D15000A9191024FBA1789A2D23BCDDF93C7D268129EA7023E6115F4DF07B:0"
            .to_string()
            .try_into()
            .unwrap(),
    };

    // TODO: verify_message_statuses should be called through gateway, like verify_messages
    let (poll_id, expiry) = test_utils::xrpl_verify_message_statuses(
        &mut protocol.app,
        &xrpl.voting_verifier_address,
        vec![(proof_msg_id.clone(), xrpl_voting_verifier::execute::MessageStatus::Succeeded)].to_vec(),
    );
    test_utils::vote_success_for_all_messages(
        &mut protocol.app,
        &xrpl.voting_verifier_address,
        1,
        &new_workers,
        poll_id,
    );
    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);
    test_utils::end_poll(&mut protocol.app, &xrpl.voting_verifier_address, poll_id);

    test_utils::xrpl_update_tx_status(
        &mut protocol.app,
        &xrpl.multisig_prover_address,
        proof_msg_id,
        xrpl_voting_verifier::execute::MessageStatus::Succeeded
    );

    let new_worker_set =
        test_utils::get_worker_set(&mut protocol.app, &xrpl.multisig_prover_address);

    assert_eq!(new_worker_set, expected_new_worker_set);
}

#[test]
fn worker_set_can_be_initialized_and_then_automatically_updated_during_proof_construction() {
    let chains = vec![
        "Ethereum".to_string().try_into().unwrap(),
        "Polygon".to_string().try_into().unwrap(),
    ];
    let (mut protocol, ethereum, _, initial_workers, min_worker_bond) =
        test_utils::setup_test_case();

    let simulated_worker_set = test_utils::workers_to_worker_set(&mut protocol, &initial_workers);

    let worker_set =
        test_utils::get_worker_set(&mut protocol.app, &ethereum.multisig_prover_address);

    assert_eq!(worker_set, simulated_worker_set);

    // add third and fourth worker
    let mut new_workers = Vec::new();
    let new_worker = Worker {
        addr: Addr::unchecked("worker3"),
        supported_chains: chains.clone(),
        key_pair: test_utils::generate_key(2),
    };
    new_workers.push(new_worker);
    let new_worker = Worker {
        addr: Addr::unchecked("worker4"),
        supported_chains: chains.clone(),
        key_pair: test_utils::generate_key(3),
    };
    new_workers.push(new_worker);

    let expected_new_worker_set = test_utils::workers_to_worker_set(&mut protocol, &new_workers);

    test_utils::register_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.multisig_address.clone(),
        protocol.governance_address.clone(),
        protocol.genesis_address.clone(),
        &new_workers,
        protocol.service_name.clone(),
        min_worker_bond,
    );

    // remove old workers
    test_utils::deregister_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.governance_address.clone(),
        &initial_workers,
        protocol.service_name.clone(),
    );

    let session_id = test_utils::construct_proof_and_sign(
        &mut protocol.app,
        &ethereum.multisig_prover_address,
        &protocol.multisig_address,
        &Vec::<Message>::new(),
        &initial_workers,
    );

    let proof = test_utils::get_proof(
        &mut protocol.app,
        &ethereum.multisig_prover_address,
        &session_id,
    );
    assert!(matches!(
        proof.status,
        multisig_prover::msg::ProofStatus::Completed { .. }
    ));

    assert_eq!(proof.message_ids.len(), 0);

    let (poll_id, expiry) = test_utils::create_worker_set_poll(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        ethereum.voting_verifier_address.clone(),
        expected_new_worker_set.clone(),
    );

    // do voting
    test_utils::vote_true_for_worker_set(
        &mut protocol.app,
        &ethereum.voting_verifier_address,
        &new_workers,
        poll_id,
    );

    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);

    test_utils::end_poll(
        &mut protocol.app,
        &ethereum.voting_verifier_address,
        poll_id,
    );

    test_utils::confirm_worker_set(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        ethereum.multisig_prover_address.clone(),
    );

    let new_worker_set =
        test_utils::get_worker_set(&mut protocol.app, &ethereum.multisig_prover_address);

    assert_eq!(new_worker_set, expected_new_worker_set);
}

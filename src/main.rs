use std::fs;

use chia::{
    bls::{PublicKey, Signature},
    protocol::{Bytes32, CoinStateFilters},
    puzzles::cat::CatArgs,
};
use chia_wallet_sdk::{
    connect_peer, create_rustls_connector, load_ssl_cert, Cat, CatSpend, Conditions, PeerOptions,
    Puzzle, SpendContext, SpendWithConditions, StandardLayer,
};
use hex_literal::hex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CoinJson {
    parent_coin_info: String,
    puzzle_hash: String,
    amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CoinSpendJson {
    coin: CoinJson,
    puzzle_reveal: String,
    solution: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpendBundleJson {
    coin_spends: Vec<CoinSpendJson>,
    aggregated_signature: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut ctx = SpendContext::new();

    let p2_puzzle_hash = Bytes32::from(hex!(
        "3fc53c4d8cf0829a84c9c3b6f08487ab8f6aacd4b7061fc1b4c202417f8a270f"
    ));

    let public_key = PublicKey::from_bytes(&hex!("b636593e666b8f049fa70d9813974d0878ef3430d2327a5cb71e99555bcf0ee7e8dad1882cfe3f6c28b1274fc886bca4"))?;
    let layer = StandardLayer::new(public_key);

    let asset_ids = vec![
        Bytes32::from(hex!(
            "7108b478ac51f79b6ebf8ce40fa695e6eb6bef654a657d2694f1183deb78cc02"
        )),
        Bytes32::from(hex!(
            "2f3a28ba03734b65797df5d5ff0e253606e7fea2e2ee341c39e9a405bce68aa8"
        )),
        Bytes32::from(hex!(
            "db1a9020d48d9d4ad22631b66ab4b9ebd3637ef7758ad38881348c5d24c38f20"
        )),
        Bytes32::from(hex!(
            "a628c1c2c6fcb74d53746157e438e108eab5c0bb3e5c80ff9b1910b3e4832913"
        )),
        Bytes32::from(hex!(
            "509deafe3cd8bbfbb9ccce1d930e3d7b57b40c964fa33379b18d628175eb7a8f"
        )),
        Bytes32::from(hex!(
            "79f6313fdb6ba66347a5bcad4af6878ac07bf5fafedeb384c3b350d913c8b6b6"
        )),
        Bytes32::from(hex!(
            "51ef89a35fa316c0f2747696b2483c9203da3155b603ea3f194640ada374907f"
        )),
        Bytes32::from(hex!(
            "8ebf855de6eb146db5602f0456d2f0cbe750d57f821b6f91a8592ee9f1d4cf31"
        )),
    ];

    let ssl = load_ssl_cert("wallet.crt", "wallet.key")?;
    let tls = create_rustls_connector(&ssl)?;
    let (peer, mut receiver) = connect_peer(
        "mainnet".to_string(),
        tls,
        "2.221.211.57:8444".parse()?,
        PeerOptions::default(),
    )
    .await?;

    tokio::spawn(async move {
        while let Some(message) = receiver.recv().await {
            println!("{:?}", message);
        }
    });

    let genesis_challenge = Bytes32::from(hex!(
        "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb"
    ));

    for asset_id in asset_ids {
        let cat_puzzle_hash = CatArgs::curry_tree_hash(asset_id, p2_puzzle_hash.into()).into();

        let coin_states = peer
            .request_puzzle_state(
                vec![cat_puzzle_hash],
                None,
                genesis_challenge,
                CoinStateFilters::new(false, true, false, 0),
                false,
            )
            .await?
            .unwrap()
            .coin_states;

        for coin_state in coin_states {
            let parent_spend = peer
                .request_puzzle_and_solution(
                    coin_state.coin.parent_coin_info,
                    coin_state.created_height.unwrap(),
                )
                .await?
                .unwrap();

            let parent_coin_state = peer
                .request_coin_state(
                    vec![coin_state.coin.parent_coin_info],
                    None,
                    genesis_challenge,
                    false,
                )
                .await?
                .unwrap()
                .coin_states[0];

            let parent_puzzle = ctx.alloc(&parent_spend.puzzle)?;
            let parent_puzzle = Puzzle::parse(&ctx.allocator, parent_puzzle);
            let parent_solution = ctx.alloc(&parent_spend.solution)?;

            let mut cats = Cat::parse_children(
                &mut ctx.allocator,
                parent_coin_state.coin,
                parent_puzzle,
                parent_solution,
            )?
            .unwrap();

            cats.retain(|cat| cat.coin.puzzle_hash == cat_puzzle_hash);

            println!("{} at {}", cats.len(), asset_id);

            let mut spends = Vec::new();

            let amount = cats.iter().fold(0, |acc, cat| acc + cat.coin.amount);

            for (i, cat) in cats.into_iter().enumerate() {
                let mut conditions = Conditions::new();

                if i == 0 {
                    conditions =
                        conditions.create_coin(p2_puzzle_hash, amount, vec![p2_puzzle_hash.into()]);
                }

                let inner_spend = layer.spend_with_conditions(&mut ctx, conditions)?;

                spends.push(CatSpend::new(cat, inner_spend));
            }

            Cat::spend_all(&mut ctx, &spends)?;
        }
    }

    let spends = ctx.take();

    let mut spend_bundle = SpendBundleJson {
        coin_spends: Vec::new(),
        aggregated_signature: format!("0x{}", hex::encode(Signature::default().to_bytes())),
    };

    for spend in spends {
        spend_bundle.coin_spends.push(CoinSpendJson {
            coin: CoinJson {
                parent_coin_info: format!(
                    "0x{}",
                    hex::encode(spend.coin.parent_coin_info.to_bytes())
                ),
                puzzle_hash: format!("0x{}", hex::encode(spend.coin.puzzle_hash.to_bytes())),
                amount: spend.coin.amount,
            },
            puzzle_reveal: hex::encode(spend.puzzle_reveal),
            solution: hex::encode(spend.solution),
        });
    }

    fs::write(
        "spend_bundle.json",
        serde_json::to_string_pretty(&spend_bundle)?,
    )?;

    Ok(())
}

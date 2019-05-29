use digest::Digest;
use std::collections::HashMap;
use std::hash::Hash;
use std::marker::PhantomData;
use vdf::VDF;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum UnicornError {
    NotCollectingSeedCommitments,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum UnicornState {
    CollectingSeedCommitments,
    SeedReady,
    VdfReady,
    RandomnessReady,
}

pub trait SeedCommitment<I: Hash + Eq + Ord> {
    fn id(&self) -> I;
    fn value(&self) -> Vec<u8>;
}

pub trait VdfResult<I: Hash + Eq + Ord> {
    fn id(&self) -> I;
    fn seed(&self) -> Vec<u8>;
    fn value(&self) -> Vec<u8>;
}

pub struct Unicorn<I: Hash + Eq + Ord, C: SeedCommitment<I>, R: VdfResult<I>, D: Digest> {
    state: UnicornState,
    seed_commitments: HashMap<I, C>,
    vdf_results: HashMap<I, R>,
    seed: Option<Vec<u8>>,
    threshold: usize,

    _digest: PhantomData<D>,
}

impl<I: Hash + Eq + Ord, C: SeedCommitment<I>, R: VdfResult<I>, D: Digest> Unicorn<I, C, R, D> {
    pub fn new(threshold: usize) -> Self {
        Unicorn {
            state: UnicornState::CollectingSeedCommitments,
            seed_commitments: HashMap::new(),
            vdf_results: HashMap::new(),
            seed: None,
            threshold,

            _digest: PhantomData,
        }
    }

    fn hash(&self, bytes: &[u8]) -> Vec<u8> {
        let mut hash = D::new();
        hash.input(bytes);
        hash.result().to_vec()
    }

    fn calculate_seed(&mut self) {
        // Sort commitments by ID for deterministic result.
        let mut commitments = self
            .seed_commitments
            .values()
            .into_iter()
            .map(|c| c)
            .collect::<Vec<_>>();
        commitments.sort_unstable_by_key(|k| k.id());

        // Create a seed by appending commitments
        let seed = commitments
            .into_iter()
            .map(|c| c.value())
            .flatten()
            .collect::<Vec<_>>();
        let seed = self.hash(&seed);

        self.seed = Some(seed.clone());
        self.state = UnicornState::SeedReady;
    }

    pub fn add_seed_commitment(&mut self, commitment: C) -> Result<(), UnicornError> {
        if self.state != UnicornState::CollectingSeedCommitments {
            return Err(UnicornError::NotCollectingSeedCommitments);
        }

        self.seed_commitments.insert(commitment.id(), commitment);

        if self.seed_commitments.len() >= self.threshold {
            self.calculate_seed();
        }

        Ok(())
    }

    pub fn state(&self) -> UnicornState {
        self.state
    }

    pub fn seed(&self) -> Option<Vec<u8>> {
        self.seed.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;
    use vdf::*;

    struct SimpleSeedCommitment {
        id: u64,
        value: Vec<u8>,
    }

    impl SeedCommitment<u64> for SimpleSeedCommitment {
        fn id(&self) -> u64 {
            self.id
        }

        fn value(&self) -> Vec<u8> {
            self.value.clone()
        }
    }

    struct SimpleVdfResult {
        id_from: u64,
        seed: Vec<u8>,
        result: Vec<u8>,
    }

    impl VdfResult<u64> for SimpleVdfResult {
        fn id(&self) -> u64 {
            self.id_from
        }

        fn seed(&self) -> Vec<u8> {
            self.seed.clone()
        }

        fn value(&self) -> Vec<u8> {
            self.result.clone()
        }
    }

    #[test]
    pub fn test_seed_creation() {
        const THRESHOLD: usize = 3;
        let mut unicorn =
            Unicorn::<u64, SimpleSeedCommitment, SimpleVdfResult, Sha256>::new(THRESHOLD);

        assert_eq!(unicorn.state(), UnicornState::CollectingSeedCommitments);

        // Generate enough seed shares
        for i in 0..THRESHOLD {
            let c = SimpleSeedCommitment {
                id: i as u64,
                value: (0..32).into_iter().map(|v| v as u8).collect(),
            };

            assert_eq!(unicorn.state(), UnicornState::CollectingSeedCommitments);
            unicorn.add_seed_commitment(c).expect("Add seed commitment");
        }

        // Seed should be ready
        assert_eq!(unicorn.state(), UnicornState::SeedReady);
        assert!(unicorn.seed().is_some());

        // Can't add commitments after seed is ready
        assert_eq!(
            unicorn.add_seed_commitment(SimpleSeedCommitment {
                id: THRESHOLD as u64 + 1u64,
                value: vec![0xDEu8, 0xADu8, 0xBEu8, 0xEFu8],
            }),
            Err(UnicornError::NotCollectingSeedCommitments)
        );

        assert_eq!(
            hex::encode(&unicorn.seed().unwrap()),
            "b11eb469e77f6577dbc8d7ca1562f599efc5701b26868d2726ae5581099df6a1"
        );
    }
}

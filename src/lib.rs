use digest::Digest;
use std::collections::HashMap;
use std::hash::Hash;
use std::marker::PhantomData;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum UnicornError {
    NotCollectingSeedCommitments,
    NotEnoughSeedCommitments,
    NotCollectingVdfResults,
    NotEnoughVdfResults,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum UnicornState {
    CollectingSeedCommitments,
    SeedReady,
    RandomnessReady,
}

pub trait SeedCommitment<I: Hash + Eq + Ord> {
    fn id(&self) -> I;
    fn value(&self) -> Vec<u8>;
}

pub trait VdfResult<I: Hash + Eq + Ord>: Clone {
    fn id(&self) -> I;
    fn seed(&self) -> Vec<u8>;
    fn value(&self) -> Vec<u8>;
}

pub struct Unicorn<I: Hash + Eq + Ord, C: SeedCommitment<I>, R: VdfResult<I>, D: Digest> {
    state: UnicornState,
    seed_commitments: HashMap<I, C>,
    vdf_results: HashMap<I, R>,
    seed: Option<Vec<u8>>,
    randomness: Option<Vec<u8>>,
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
            randomness: None,
            threshold,

            _digest: PhantomData,
        }
    }

    fn hash(&self, bytes: &[u8]) -> Vec<u8> {
        let mut hash = D::new();
        hash.input(bytes);
        hash.result().to_vec()
    }

    fn calculate_seed(&mut self) -> Vec<u8> {
        // Sort commitments by ID for deterministic result
        let mut commitments = self
            .seed_commitments
            .values()
            .into_iter()
            .map(|c| c)
            .collect::<Vec<_>>();
        commitments.sort_unstable_by_key(|k| k.id());

        // Create the seed by appending commitments and hashing them
        let seed = commitments
            .into_iter()
            .map(|c| c.value())
            .flatten()
            .collect::<Vec<_>>();

        self.hash(&seed)
    }

    pub fn finalize_seed(&mut self) -> Result<(), UnicornError> {
        if self.seed_commitments.len() >= self.threshold {
            self.seed = Some(self.calculate_seed());
            self.state = UnicornState::SeedReady;
        } else {
            return Err(UnicornError::NotEnoughSeedCommitments);
        }

        return Ok(());
    }

    pub fn add_seed_commitment(&mut self, commitment: C) -> Result<(), UnicornError> {
        if self.state != UnicornState::CollectingSeedCommitments {
            return Err(UnicornError::NotCollectingSeedCommitments);
        }

        self.seed_commitments.insert(commitment.id(), commitment);

        Ok(())
    }

    pub fn add_vdf_result(&mut self, vdf_result: R) -> Result<(), UnicornError> {
        if self.state != UnicornState::SeedReady {
            return Err(UnicornError::NotCollectingVdfResults);
        }

        self.vdf_results.insert(vdf_result.id(), vdf_result);

        Ok(())
    }

    fn most_frequent_vdf_result(&mut self) -> Option<(Vec<u8>, usize)> {
        let mut freq_map = HashMap::<Vec<u8>, usize>::new();

        for res in self.vdf_results.values() {
            *freq_map.entry(res.value()).or_insert(0) += 1;
        }

        let mut freq_vec = freq_map.into_iter().collect::<Vec<_>>();
        freq_vec.sort_unstable_by_key(|(_, freq)| *freq);

        freq_vec.first().cloned()
    }

    pub fn finalize_vdf_result(&mut self) -> Result<(), UnicornError> {
        if let Some((res, freq)) = self.most_frequent_vdf_result() {
            if freq < self.threshold {
                return Err(UnicornError::NotEnoughVdfResults);
            }

            self.randomness = Some(self.hash(&res));
            self.state = UnicornState::RandomnessReady;
        } else {
            return Err(UnicornError::NotEnoughVdfResults);
        }

        return Ok(());
    }

    pub fn state(&self) -> UnicornState {
        self.state
    }

    pub fn seed(&self) -> Option<Vec<u8>> {
        self.seed.clone()
    }

    pub fn reset(self) -> Self {
        Self {
            state: UnicornState::CollectingSeedCommitments,
            seed_commitments: Default::default(),
            vdf_results: Default::default(),
            seed: None,
            randomness: None,
            threshold: self.threshold,
            _digest: PhantomData,
        }
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

    #[derive(Debug, Clone)]
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

    type SimpleUnicorn = Unicorn<u64, SimpleSeedCommitment, SimpleVdfResult, Sha256>;

    fn seed_unicorn_with(
        unicorn: &mut SimpleUnicorn,
        commitments: Vec<SimpleSeedCommitment>,
    ) -> Result<(), UnicornError> {
        // Generate enough seed shares
        for sc in commitments {
            assert_eq!(unicorn.state(), UnicornState::CollectingSeedCommitments);
            unicorn.add_seed_commitment(sc)?;
        }

        Ok(())
    }

    #[test]
    pub fn test_not_enough_seed_commitments() {
        const THRESHOLD: usize = 3;
        let mut unicorn = SimpleUnicorn::new(THRESHOLD);

        // 1 of 3 seed commitments
        let commitments = vec![SimpleSeedCommitment {
            id: 0,
            value: vec![0u8, 0u8, 0u8],
        }];

        assert!(seed_unicorn_with(&mut unicorn, commitments).is_ok());

        // Should be unable to produce seed
        assert_eq!(
            unicorn.finalize_seed(),
            Err(UnicornError::NotEnoughSeedCommitments)
        );
    }

    #[test]
    pub fn test_more_seed_commitments() {
        const THRESHOLD: usize = 3;
        let mut unicorn = SimpleUnicorn::new(THRESHOLD);

        // 5 of 3 seed commitments
        let commitments = vec![
            SimpleSeedCommitment {
                id: 0,
                value: vec![0u8, 0u8, 0u8],
            },
            SimpleSeedCommitment {
                id: 1,
                value: vec![1u8, 1u8, 1u8],
            },
            SimpleSeedCommitment {
                id: 2,
                value: vec![2u8, 2u8, 2u8],
            },
            SimpleSeedCommitment {
                id: 3,
                value: vec![3u8, 3u8, 3u8],
            },
            SimpleSeedCommitment {
                id: 4,
                value: vec![4u8, 4u8, 4u8],
            },
        ];

        assert!(seed_unicorn_with(&mut unicorn, commitments).is_ok());

        // Finalize seed
        assert!(unicorn.finalize_seed().is_ok());

        // Seed should be ready
        assert_eq!(unicorn.state(), UnicornState::SeedReady);
        assert!(unicorn.seed().is_some());
        assert_eq!(
            hex::encode(&unicorn.seed().unwrap()),
            "8d84c7b55695b4ac9ef8a92224a64f449107a4027dd763587003fc65a664f4ce"
        );
    }

    #[test]
    pub fn test_seed_creation() {
        const THRESHOLD: usize = 3;
        let mut unicorn = SimpleUnicorn::new(THRESHOLD);

        // Shouldn't be able to produce seed too early
        assert_eq!(
            unicorn.finalize_seed(),
            Err(UnicornError::NotEnoughSeedCommitments)
        );

        let commitments = vec![
            SimpleSeedCommitment {
                id: 0,
                value: vec![0u8, 0u8, 0u8],
            },
            SimpleSeedCommitment {
                id: 1,
                value: vec![1u8, 1u8, 1u8],
            },
            SimpleSeedCommitment {
                id: 2,
                value: vec![2u8, 2u8, 2u8],
            },
        ];

        assert!(seed_unicorn_with(&mut unicorn, commitments).is_ok());

        // Finalize seed
        assert!(unicorn.finalize_seed().is_ok());

        // Seed should be ready
        assert_eq!(unicorn.state(), UnicornState::SeedReady);
        assert!(unicorn.seed().is_some());
        assert_eq!(
            hex::encode(&unicorn.seed().unwrap()),
            "4333ddceb169e2f1741ae48779c9b647154fd69affc8b61f050de97a87945ba3"
        );
    }

    #[test]
    pub fn test_vdf_results() {
        const THRESHOLD: usize = 3;
        let mut unicorn = SimpleUnicorn::new(THRESHOLD);

        let commitments = vec![
            SimpleSeedCommitment {
                id: 0,
                value: vec![0u8, 0u8, 0u8],
            },
            SimpleSeedCommitment {
                id: 1,
                value: vec![1u8, 1u8, 1u8],
            },
            SimpleSeedCommitment {
                id: 2,
                value: vec![2u8, 2u8, 2u8],
            },
        ];

        seed_unicorn_with(&mut unicorn, commitments).unwrap();
        unicorn.finalize_seed().unwrap();

        let seed = unicorn.seed().unwrap();
        let vdf = vdf::PietrzakVDFParams(1024).new();
        let vdf_result = (0..THRESHOLD)
            .into_iter()
            .map(|_| vdf.solve(&seed, 1_000).unwrap())
            .enumerate()
            .map(|(id, res)| SimpleVdfResult {
                id_from: id as u64,
                seed: seed.clone(),
                result: res.clone(),
            })
            .collect::<Vec<_>>();

        for res in vdf_result.into_iter() {
            unicorn.add_vdf_result(res).unwrap();
        }

        assert!(unicorn.finalize_vdf_result().is_ok());
        let randomness = unicorn.randomness.unwrap();
        let randomness = hex::encode(&randomness);

        assert_eq!(
            randomness,
            "5eade8103071b0421c012c771fe92b5939101682ac0b321d98a57c16a96efe23"
        );
    }
}

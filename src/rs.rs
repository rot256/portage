use reed_solomon_erasure::galois_16::Field;
use reed_solomon_erasure::ReedSolomon;

use std::iter::FromIterator;

use super::SHARD_ELEMS;
use super::{File, Header, Shard};

impl AsRef<[[u8; 2]]> for Shard {
    fn as_ref(&self) -> &[[u8; 2]] {
        &self.coords[..]
    }
}

impl AsMut<[[u8; 2]]> for Shard {
    fn as_mut(&mut self) -> &mut [[u8; 2]] {
        &mut self.coords[..]
    }
}

impl FromIterator<[u8; 2]> for Shard {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = [u8; 2]>,
    {
        let mut shard = Shard {
            idx: 0,
            coords: [[0u8; 2]; SHARD_ELEMS],
        };

        let mut iter = iter.into_iter();
        for i in 0..SHARD_ELEMS {
            if let Some(coord) = iter.next() {
                shard.coords[i] = coord
            }
        }

        shard
    }
}

impl File {
    pub fn reconstruct(header: &Header, shards: &[Shard]) -> Result<Self, ()> {
        // check that sufficient data to reconstruct
        let dimension = header.shards();
        if dimension > shards.len() {
            return Err(());
        }

        // obtain maximum shard index
        let mut max: usize = 0;
        for s in shards {
            let idx = s.idx as usize;
            if idx > max {
                max = idx;
            }
        }

        // create sparse vector of shards
        let mut sparse = Vec::with_capacity(max + 1);
        sparse.resize(max + 1, None);
        for s in shards {
            assert!(sparse[s.idx as usize].is_none());
            sparse[s.idx as usize] = Some(s.clone());
        }

        // create RS instance
        let rs: ReedSolomon<Field> = ReedSolomon::new(dimension, (max + 1) - dimension).unwrap();

        // reconstruct data shards
        rs.reconstruct_data(&mut sparse).map_err(|_| ())?;

        // pack into file
        let mut shards: Vec<Shard> = Vec::with_capacity(dimension);
        for i in 0..dimension {
            let mut coord = sparse[i].unwrap();
            coord.idx = i as u16;
            shards.push(coord);
        }
        Ok(File {
            length: header.length,
            shards,
        })
    }

    pub fn shards(&self, expansion: usize) -> (Header, Vec<Shard>) {
        // create header
        let header = Header {
            length: self.length,
        };
        let dimension = header.shards();

        // create codeword buffer
        let code_len = dimension + expansion;
        let mut code = Vec::with_capacity(code_len);
        for i in 0..code_len {
            if i < dimension {
                code.push(self.shards[i].clone());
            } else {
                code.push(Shard {
                    idx: i as u16,
                    coords: [Default::default(); SHARD_ELEMS],
                });
            }
        }

        // use RS coding to extend and create new shards
        if expansion > 0 {
            let rs: ReedSolomon<Field> = ReedSolomon::new(dimension, expansion).unwrap();
            rs.encode(&mut code).unwrap();
        }
        (header, code)
    }
}

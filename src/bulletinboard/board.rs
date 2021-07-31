// SPDX-FileCopyrightText: 2021 David Ruescas <david@nvotes.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::path::Path;

use crate::bulletinboard::mixnetboard::BBError;

pub trait Board {
    fn list(&self) -> Result<Vec<String>, BBError>;
    fn get(&self, target: String) -> Result<Option<Vec<u8>>, BBError>;
    fn add(&mut self, entries: Vec<(&Path, Vec<u8>)>, message: String) -> Result<(), BBError>;
    fn post(&self) -> Result<(), BBError>;
    fn get_unsafe(&self, target: &str) -> Result<Option<Vec<u8>>, BBError>;
}

#[derive(Default)]
pub struct MBoard {
    data: HashMap<String, Vec<u8>>,
}

impl Board for MBoard {
    fn list(&self) -> Result<Vec<String>, BBError> {
        Ok(self.data.iter().map(|(a, _)| a.clone()).collect())
    }
    fn get(&self, target: String) -> Result<Option<Vec<u8>>, BBError> {
        Ok(self.data.get(&target).map(|v| v.to_vec()))
    }
    fn add(&mut self, entries: Vec<(&Path, Vec<u8>)>, _message: String) -> Result<(), BBError> {
        for (name, data) in entries {
            let key = name
                .to_str()
                .ok_or_else(|| BBError::Msg("Invalid path string when putting".to_string()))?
                .to_string();
            if self.data.contains_key(&key) {
                panic!(
                    "Attempted to overwrite bulletin board value for key '{}'",
                    key
                );
            }
            self.data.insert(key, data.to_vec());
        }

        Ok(())
    }

    fn post(&self) -> Result<(), BBError> {
        Ok(())
    }
    fn get_unsafe(&self, target: &str) -> Result<Option<Vec<u8>>, BBError> {
        Ok(self.data.get(target).map(|v| v.to_vec()))
    }
    /* fn get_config_type(&self, target: &str) -> Option<bool> {
        let bytes = self.data.get(target)?;
        // let config_rug = bincode::deserialize::<Config<Integer, RugGroup>>(bytes);
        let config_rug = Config::<Integer, RugGroup>::deser(bytes);

        // let config_ristretto = bincode::deserialize::<Config<RistrettoPoint, RistrettoGroup>>(bytes);
        let config_ristretto = Config::<RistrettoPoint, RistrettoGroup>::deser(bytes);
        if config_rug.is_ok() {
            Some(true)
        }
        else if config_ristretto.is_ok() {
            Some(false)
        }
        else {
            None
        }
    }
    fn clear(&mut self) {
        self.data.clear();
    }*/
}

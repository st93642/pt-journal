/*****************************************************************************/
/*                                                                           */
/*  store.rs                                             TTTTTTTT SSSSSSS II */
/*                                                          TT    SS      II */
/*  By: st93642@students.tsi.lv                             TT    SSSSSSS II */
/*                                                          TT         SS II */
/*  Created: Nov 21 2025 23:43 st93642                      TT    SSSSSSS II */
/*  Updated: Nov 27 2025 18:18 st93642                                       */
/*                                                                           */
/*   Transport and Telecommunication Institute - Riga, Latvia                */
/*                       https://tsi.lv                                      */
/*****************************************************************************/

use crate::model::*;
use anyhow::Result;
use std::path::Path;

pub fn load_session(path: &Path) -> Result<Session> {
    let content = std::fs::read_to_string(path)?;
    let session: Session = serde_json::from_str(&content)?;

    Ok(session)
}

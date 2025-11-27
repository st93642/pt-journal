/*****************************************************************************/
/*                                                                           */
/*  store.rs                                             TTTTTTTT SSSSSSS II */
/*                                                          TT    SS      II */
/*  By: st93642@students.tsi.lv                             TT    SSSSSSS II */
/*                                                          TT         SS II */
/*  Created: Nov 21 2025 23:43 st93642                      TT    SSSSSSS II */
/*  Updated: Nov 27 2025 00:27 st93642                                       */
/*                                                                           */
/*   Transport and Telecommunication Institute - Riga, Latvia                */
/*                       https://tsi.lv                                      */
/*****************************************************************************/

use crate::model::*;
use anyhow::Result;
use std::path::Path;

#[allow(dead_code)]
pub fn load_session(path: &Path) -> Result<Session> {
    let content = std::fs::read_to_string(path)?;
    let mut session: Session = serde_json::from_str(&content)?;

    // Migrate legacy step data to new StepContent format
    for phase in &mut session.phases {
        for step in &mut phase.steps {
            step.migrate_from_legacy();
        }
    }

    Ok(session)
}

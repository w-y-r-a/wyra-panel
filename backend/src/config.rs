use once_cell::sync::OnceCell;
use std::env::var;

/*
//! # Format:
//! ```rust
//! pub(crate) static <ENV_VARIABLE_NAME>: OnceCell<String> = OnceCell::new();
//! ```
 */

pub(crate) static PANEL_VERSION: OnceCell<String> = OnceCell::new();

pub(crate) fn init_config() {
    // Format for this:
    // ```rust
    // let _ = <ENV_VARIABLE_NAME>.set(var("<ENV_VARIABLE_NAME>").expect("<ENV_VARIABLE_NAME> not set"));
    //```
    
    let _ = PANEL_VERSION.set(var("PANEL_VERSION").expect("PANEL_VERSION not set"));
}
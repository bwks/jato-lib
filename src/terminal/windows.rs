//! Windows console modes for an interactive shell: virtual-terminal input, so keys arrive as
//! the VT byte sequences a remote shell expects, and virtual-terminal output, so the console
//! draws the escape sequences the shell sends.
//!
//! The console calls go through `crossterm_winapi`'s safe wrappers, as crossterm's own raw
//! mode does, so Jato has no `unsafe` code.

use std::io;

use crossterm_winapi::{ConsoleMode, Handle};

/// `ENABLE_VIRTUAL_TERMINAL_INPUT`: the console reports keys as VT sequences.
const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;
/// `ENABLE_VIRTUAL_TERMINAL_PROCESSING`: the console draws VT sequences it is sent.
const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

/// The console modes before [`enable_virtual_terminal`], for [`restore`].
pub(crate) struct ConsoleModes {
    input: u32,
    output: u32,
}

/// Turn on virtual-terminal input and output, keeping the other mode flags.
pub(crate) fn enable_virtual_terminal() -> io::Result<ConsoleModes> {
    let input = input_console()?;
    let output = output_console()?;
    let modes = ConsoleModes {
        input: input.mode()?,
        output: output.mode()?,
    };
    input.set_mode(modes.input | ENABLE_VIRTUAL_TERMINAL_INPUT)?;
    if let Err(error) = output.set_mode(modes.output | ENABLE_VIRTUAL_TERMINAL_PROCESSING) {
        if let Err(restore) = input.set_mode(modes.input) {
            tracing::warn!(error = %restore, "failed to restore the console input mode");
        }
        return Err(error);
    }
    Ok(modes)
}

/// Put back the modes [`enable_virtual_terminal`] found.
pub(crate) fn restore(modes: &ConsoleModes) -> io::Result<()> {
    input_console()?.set_mode(modes.input)?;
    output_console()?.set_mode(modes.output)
}

/// The console behind standard input.
fn input_console() -> io::Result<ConsoleMode> {
    Ok(ConsoleMode::from(Handle::input_handle()?))
}

/// The console behind standard output.
fn output_console() -> io::Result<ConsoleMode> {
    Ok(ConsoleMode::from(Handle::output_handle()?))
}

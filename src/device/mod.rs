//! Device CLIs: driving a network device's command line through a shell, with a profile that
//! describes its prompts and commands.
mod cli;
mod profile;
mod profiles;

pub use cli::{Device, DeviceOptions};
pub use profile::{ConfigMode, DeviceProfile, Mode};

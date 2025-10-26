# Sony TV Remote

A cross-platform Tauri application to control Sony TVs remotely from Mac, iPad, and iPhone.

## Features

- Control Sony TV power, volume, channels, mute, and input
- Simple web-based UI
- Cross-platform support (macOS, Windows, Linux, and mobile with additional setup)

## Prerequisites

- Rust (installed)
- Tauri CLI (`cargo install tauri-cli`)

## Setup

1. Clone or navigate to the project directory.
2. Build the backend: `cd src-tauri && cargo build`
3. Run in development: `cargo tauri dev`

## Usage

1. Launch the app.
2. Enter your Sony TV's IP address (find it in TV settings > Network).
3. Click the buttons to control the TV.

Note: Ensure the TV and device are on the same network, and IP control is enabled on the TV.

## Building for Production

- Desktop: `cargo tauri build`
- Mobile: Requires additional setup for iOS/Android. See Tauri documentation.

## Troubleshooting

- If commands don't work, verify the TV IP and that IP control is enabled.
- Check console for errors.

## License

MIT# MyTVRemote

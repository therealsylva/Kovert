use std::collections::VecDeque;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use evdev::{Device, EventType};
use kovert_core::config::HotkeyConfig;
use kovert_core::event::{Event, EventKind};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub fn spawn(config: HotkeyConfig, sender: mpsc::Sender<Event>) -> Result<JoinHandle<()>> {
    let sequence: Vec<u16> = config
        .sequence
        .iter()
        .map(|key| key_code(key).ok_or_else(|| anyhow!("unsupported key name: {key}")))
        .collect::<Result<_>>()?;
    let device = Device::open(&config.device)
        .with_context(|| format!("open input device {}", config.device.display()))?;
    let mut stream = device
        .into_event_stream()
        .context("create asynchronous input stream")?;
    Ok(tokio::spawn(async move {
        let mut buffer: VecDeque<(u16, Instant)> = VecDeque::with_capacity(sequence.len());
        loop {
            let event = match stream.next_event().await {
                Ok(event) => event,
                Err(error) => {
                    let _ = sender
                        .send(Event::new(
                            "hotkeys",
                            EventKind::SensorFailure {
                                sensor: "hotkeys".to_owned(),
                                message: error.to_string(),
                            },
                        ))
                        .await;
                    return;
                }
            };
            if event.event_type() != EventType::KEY || event.value() != 1 {
                continue;
            }
            let now = Instant::now();
            buffer.push_back((event.code(), now));
            while buffer.len() > sequence.len() {
                buffer.pop_front();
            }
            while buffer
                .front()
                .is_some_and(|(_, at)| now.duration_since(*at) > config.within)
            {
                buffer.pop_front();
            }
            if buffer.len() == sequence.len()
                && buffer
                    .iter()
                    .map(|(code, _)| *code)
                    .eq(sequence.iter().copied())
            {
                buffer.clear();
                if sender
                    .send(Event::new(
                        "hotkeys",
                        EventKind::Hotkey {
                            name: config.name.clone(),
                        },
                    ))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }))
}

fn key_code(name: &str) -> Option<u16> {
    let normalized = name.trim().to_ascii_uppercase();
    let value = normalized.strip_prefix("KEY_").unwrap_or(&normalized);
    Some(match value {
        "ESC" => 1,
        "1" => 2,
        "2" => 3,
        "3" => 4,
        "4" => 5,
        "5" => 6,
        "6" => 7,
        "7" => 8,
        "8" => 9,
        "9" => 10,
        "0" => 11,
        "Q" => 16,
        "W" => 17,
        "E" => 18,
        "R" => 19,
        "T" => 20,
        "Y" => 21,
        "U" => 22,
        "I" => 23,
        "O" => 24,
        "P" => 25,
        "ENTER" => 28,
        "LEFTCTRL" | "CTRL" => 29,
        "A" => 30,
        "S" => 31,
        "D" => 32,
        "F" => 33,
        "G" => 34,
        "H" => 35,
        "J" => 36,
        "K" => 37,
        "L" => 38,
        "LEFTSHIFT" | "SHIFT" => 42,
        "Z" => 44,
        "X" => 45,
        "C" => 46,
        "V" => 47,
        "B" => 48,
        "N" => 49,
        "M" => 50,
        "LEFTALT" | "ALT" => 56,
        "SPACE" => 57,
        "F1" => 59,
        "F2" => 60,
        "F3" => 61,
        "F4" => 62,
        "F5" => 63,
        "F6" => 64,
        "F7" => 65,
        "F8" => 66,
        "F9" => 67,
        "F10" => 68,
        "F11" => 87,
        "F12" => 88,
        "RIGHTCTRL" => 97,
        "RIGHTALT" => 100,
        "HOME" => 102,
        "UP" => 103,
        "PAGEUP" => 104,
        "LEFT" => 105,
        "RIGHT" => 106,
        "END" => 107,
        "DOWN" => 108,
        "PAGEDOWN" => 109,
        "INSERT" => 110,
        "DELETE" => 111,
        "LEFTMETA" | "META" => 125,
        "RIGHTMETA" => 126,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_documented_key_names() {
        assert_eq!(key_code("KEY_LEFTCTRL"), Some(29));
        assert_eq!(key_code("x"), Some(45));
        assert_eq!(key_code("unknown"), None);
    }
}

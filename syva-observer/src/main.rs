use std::env;

use syva_core::{StatusRequest, WatchEventsRequest};
use syva_core_client::{connect_unix_socket_with_retry, syva_core};
use syva_observer::ObserverState;

const DEFAULT_SOCKET: &str = "/run/syva/syva-core.sock";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = env::var("SYVA_CORE_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.into());
    loop {
        let mut client = connect_unix_socket_with_retry(socket.clone().into()).await;
        let status = match client.status(StatusRequest {}).await {
            Ok(response) => response.into_inner(),
            Err(error) => {
                eprintln!("syva-core status failed; reconnecting: {error}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };
        let mut state = ObserverState::from_status(status);
        println!(
            "posture={:?} generation={}",
            state.posture(),
            state.enforcement.generation
        );

        let mut events = match client
            .watch_events(WatchEventsRequest { follow: true })
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => {
                eprintln!("syva-core event stream failed; reconnecting: {error}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };
        loop {
            match events.message().await {
                Ok(Some(event)) => state.push_event(event),
                Ok(None) => break,
                Err(error) => {
                    eprintln!("syva-core event stream read failed; reconnecting: {error}");
                    break;
                }
            }
        }
        eprintln!("syva-core event stream ended; reconnecting");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

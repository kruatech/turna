//! PacketHandler implementation for io_uring worker threads.
//! Handles both main TURN socket and relay socket packets.

#![cfg(all(target_os = "linux", feature = "io-uring"))]

use crate::processor::{Action, ClusterRouting, PacketProcessor};
use std::net::SocketAddr;
use std::sync::Arc;
use turna_auth::AuthMode;
use turna_health::Metrics;
use turna_session::AllocationStore;
use turna_transport::worker::{ForwardAction, PacketHandler};

/// TURN packet handler for io_uring workers.
pub struct RelayHandler {
    processor: Arc<PacketProcessor>,
    external_ip: std::net::IpAddr,
}

impl RelayHandler {
    pub fn new(
        store: Arc<AllocationStore>,
        auth: Arc<AuthMode>,
        external_ip: std::net::IpAddr,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self::new_with_cluster(store, auth, external_ip, metrics, None)
    }

    pub fn new_with_cluster(
        store: Arc<AllocationStore>,
        auth: Arc<AuthMode>,
        external_ip: std::net::IpAddr,
        metrics: Arc<Metrics>,
        cluster: Option<ClusterRouting>,
    ) -> Self {
        Self {
            processor: Arc::new(PacketProcessor::new_with_cluster(
                store,
                auth,
                external_ip,
                metrics,
                cluster,
            )),
            external_ip,
        }
    }

    /// Map a single `Action` to a `ForwardAction` for the io_uring send path.
    fn convert_action(&self, action: Action) -> ForwardAction {
        match action {
            Action::Send { data, target } => ForwardAction::Send { data, target },

            // Action::Forward replaces the old ZeroCopyForward{offset, len}.
            // data is already a Bytes::slice() — no copy in the io_uring path either.
            Action::Forward {
                data,
                target,
                relay_port,
            } => ForwardAction::SendViaRelay {
                data,
                target,
                relay_port,
            },

            Action::SendViaRelay {
                data,
                target,
                relay_port,
            } => ForwardAction::SendViaRelay {
                data,
                target,
                relay_port,
            },

            // The io_uring/worker path binds its own relay socket, so the
            // pre-bound socket from handle_allocate is dropped here (closed),
            // freeing the port for the worker to rebind. CloseRelay has no
            // worker equivalent yet — the worker path keeps its prior
            // (non-transactional) relay lifecycle.
            Action::RegisterRelay { port, .. } => ForwardAction::CreateRelay { port },

            Action::CloseRelay { port } => ForwardAction::CloseRelay { port },

            Action::None => ForwardAction::None,
        }
    }

    fn convert_actions(&self, actions: Vec<Action>) -> ForwardAction {
        if actions.len() == 1 {
            return self.convert_action(actions.into_iter().next().unwrap());
        }
        let converted: Vec<ForwardAction> = actions
            .into_iter()
            .map(|a| self.convert_action(a))
            .filter(|a| !matches!(a, ForwardAction::None))
            .collect();

        match converted.len() {
            0 => ForwardAction::None,
            1 => converted.into_iter().next().unwrap(),
            _ => ForwardAction::Multi(converted),
        }
    }
}

impl PacketHandler for RelayHandler {
    fn handle_packet(&mut self, data: &[u8], source: SocketAddr) -> ForwardAction {
        // In the io_uring path the kernel already did the zero-copy work
        // (registered buffers + fixed file descriptors). We copy once here
        // to satisfy the process() signature; real zero-copy happens at the
        // send side via ZeroCopyViaRelay in the uring engine.
        let actions = self.processor.process_slice(data, source);
        self.convert_actions(actions)
    }

    fn handle_relay_packet(
        &mut self,
        data: &[u8],
        source: SocketAddr,
        relay_port: u16,
    ) -> ForwardAction {
        let relay_addr = SocketAddr::new(self.external_ip, relay_port);
        let actions = self.processor.process_relay_recv(data, source, relay_addr);
        self.convert_actions(actions)
    }
}

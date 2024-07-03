use crate::vfsext::NFSFileSystemExtended;
use std::fmt;
use std::sync::Arc;
use tokio::sync::mpsc;
#[derive(Clone)]
pub struct RPCContext {
    pub local_port: u16,
    pub client_addr: String,
    pub auth: crate::rpc::auth_unix,
    pub vfs: Arc<dyn NFSFileSystemExtended + Send + Sync>,
    pub mount_signal: Option<mpsc::Sender<bool>>,
}

impl fmt::Debug for RPCContext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RPCContext")
            .field("local_port", &self.local_port)
            .field("client_addr", &self.client_addr)
            .field("auth", &self.auth)
            .finish()
    }
}

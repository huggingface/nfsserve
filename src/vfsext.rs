use crate::nfs::*;
use crate::nfs;
use crate::vfs::*;
use crate::rpc::auth_unix;

use async_trait::async_trait;

#[derive(Clone, Debug, Default)]
pub struct UserContext {
    _uid: u32,
    _gid: u32,
    _gids: Vec<u32>,
}

impl UserContext {
    pub fn new(uid: u32, gid: u32, gids: Vec<u32>) -> Self {
        Self { _uid: uid, _gid: gid, _gids: gids }
    }
}

impl From<&auth_unix> for UserContext {
    fn from(auth: &auth_unix) -> Self {
        Self { _uid: auth.uid, _gid: auth.gid, _gids: auth.gids.clone() }
    }
}

#[async_trait]
pub trait NFSFileSystemExtended : Sync {

    /// Returns the set of capabilities supported.
    fn capabilities(&self) -> VFSCapabilities;

    /// Returns the ID the of the root directory "/".
    fn root_dir(&self) -> fileid3;

    /// Look up the ID of a path in a directory.
    ///
    /// i.e. given a directory dir/ containing a file a.txt
    /// this may call lookup(id_of("dir/"), "a.txt")
    /// and this should return the id of the file "dir/a.txt"
    /// For example, given a directory `dir/` containing a file `a.txt`,
    /// a call to `lookup(id_of("dir/"), "a.txt")` should return the ID
    /// of the file `dir/a.txt`.
    ///
    /// This method should be fast as it is used very frequently.
    async fn lookup(&self, dirid: fileid3, filename: &filename3, user_ctx : &UserContext, dir_attr : &mut post_op_attr, obj_attr : &mut post_op_attr) -> Result<fileid3, nfsstat3>;

    /// Returns the attributes of the entity identified by 'id'.
    /// This method should be fast as it is used very frequently.
    async fn getattr(&self, id: fileid3, user_ctx : &UserContext) -> Result<fattr3, nfsstat3>;

    /// Sets the attributes of an id
    /// this should return Err(nfsstat3::NFS3ERR_ROFS) if readonly
    async fn setattr(&self, id: fileid3, setattr: sattr3, user_ctx : &UserContext) -> Result<fattr3, nfsstat3>;

    /// Checks access permissions
    async fn access(&self, id: fileid3, access : u32, user_ctx : &UserContext, obj_attr : &mut post_op_attr) -> Result<u32, nfsstat3>;

    /// Reads the contents of a file returning (bytes, EOF)
    /// Note that offset/count may go past the end of the file and that
    /// in that case, all bytes till the end of file are returned.
    /// EOF must be flagged if the end of the file is reached by the read.
    async fn read(&self, id: fileid3, offset: u64, count: u32, user_ctx : &UserContext, obj_attr : &mut post_op_attr)
        -> Result<(Vec<u8>, bool), nfsstat3>;

    /// Writes the contents of a file returning (bytes, EOF)
    /// Note that offset/count may go past the end of the file and that
    /// in that case, the file is extended.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn write(&self, id: fileid3, offset: u64, data: &[u8], user_ctx : &UserContext, obj_attr : &mut pre_op_attr) -> Result<fattr3, nfsstat3>;

    /// Creates a file with the following attributes.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn create(
        &self,
        dirid: fileid3,
        filename: &filename3,
        attr: sattr3,
        user_ctx : &UserContext,
        pre_dir_attr : &mut pre_op_attr,
        post_dir_attr : &mut post_op_attr,
    ) -> Result<(fileid3, fattr3), nfsstat3>;

    /// Creates a file if it does not already exist
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn create_exclusive(
        &self,
        dirid: fileid3,
        filename: &filename3,
        user_ctx : &UserContext,
        pre_dir_attr : &mut pre_op_attr,
        post_dir_attr : &mut post_op_attr,
    ) -> Result<fileid3, nfsstat3>;

    /// Makes a directory with the following attributes.
    /// If not supported dur to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn mkdir(
        &self,
        dirid: fileid3,
        dirname: &filename3,
        user_ctx : &UserContext,
        pre_dir_attr : &mut pre_op_attr,
        post_dir_attr : &mut post_op_attr,
    ) -> Result<(fileid3, fattr3), nfsstat3>;

    /// Removes a file.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn remove(&self, dirid: fileid3, filename: &filename3, user_ctx : &UserContext, pre_dir_attr : &mut pre_op_attr, post_dir_attr : &mut post_op_attr) -> Result<(), nfsstat3>;

    /// Removes a file.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
        user_ctx : &UserContext,
        pre_from_dir_attr : &mut pre_op_attr,
        pre_to_dir_attr : &mut pre_op_attr,
        post_from_dir_attr : &mut post_op_attr,
        post_to_dir_attr : &mut post_op_attr,
    ) -> Result<(), nfsstat3>;

    /// Returns the contents of a directory with pagination.
    /// Directory listing should be deterministic.
    /// Up to max_entries may be returned, and start_after is used
    /// to determine where to start returning entries from.
    ///
    /// For instance if the directory has entry with ids [1,6,2,11,8,9]
    /// and start_after=6, readdir should returning 2,11,8,...
    //
    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
        user_ctx : &UserContext,
    ) -> Result<ReadDirResult, nfsstat3>;

    /// Simple version of readdir.
    /// Only need to return filename and id
    async fn readdir_simple(
        &self,
        dirid: fileid3,
        count: usize,
        user_ctx : &UserContext,
    ) -> Result<ReadDirSimpleResult, nfsstat3> {
        Ok(ReadDirSimpleResult::from_readdir_result(
            &self.readdir(dirid, 0, count, user_ctx).await?,
        ))
    }

    /// Makes a symlink with the following attributes.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn symlink(
        &self,
        dirid: fileid3,
        linkname: &filename3,
        symlink: &nfspath3,
        attr: &sattr3,
        user_ctx : &UserContext,
        pre_obj_attr : &mut pre_op_attr,
        post_obj_attr : &mut post_op_attr,
    ) -> Result<(fileid3, fattr3), nfsstat3>;

    /// Reads a symlink
    async fn readlink(&self, id: fileid3, user_ctx: &UserContext, symlink_attr : &mut post_op_attr) -> Result<nfspath3, nfsstat3>;

    /// Get static file system Information
    async fn fsinfo(
        &self,
        root_fileid: fileid3,
        user_ctx : &UserContext,
    ) -> Result<fsinfo3, nfsstat3> {

        let dir_attr: nfs::post_op_attr = match self.getattr(root_fileid, user_ctx).await {
            Ok(v) => nfs::post_op_attr::attributes(v),
            Err(_) => nfs::post_op_attr::Void,
        };

        let res = fsinfo3 {
            obj_attributes: dir_attr,
            rtmax: 1024 * 1024,
            rtpref: 1024 * 124,
            rtmult: 1024 * 1024,
            wtmax: 1024 * 1024,
            wtpref: 1024 * 1024,
            wtmult: 1024 * 1024,
            dtpref: 1024 * 1024,
            maxfilesize: 128 * 1024 * 1024 * 1024,
            time_delta: nfs::nfstime3 {
                seconds: 0,
                nseconds: 1000000,
            },
            properties: nfs::FSF_SYMLINK | nfs::FSF_HOMOGENEOUS | nfs::FSF_CANSETTIME,
        };
        Ok(res)
    }

    /// Converts the fileid to an opaque NFS file handle. Optional.
    fn id_to_fh(&self, id: fileid3) -> nfs_fh3;

    /// Converts an opaque NFS file handle to a fileid.  Optional.
    fn fh_to_id(&self, id: &nfs_fh3) -> Result<fileid3, nfsstat3>;

    /// Converts a complete path to a fileid.  Optional.
    /// The default implementation walks the directory structure with lookup()
    async fn path_to_id(&self, path: &[u8]) -> Result<fileid3, nfsstat3>;

    fn serverid(&self) -> cookieverf3;
}

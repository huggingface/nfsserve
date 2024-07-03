use crate::nfs::*;
use crate::vfsext::NFSFileSystemExtended;
use crate::vfsext::UserContext;
use crate::vfs::*;
use async_trait::async_trait;
use std::sync::Arc;

pub struct DefaultNFSFileSystemExtended {
   pub vfs: Arc<dyn NFSFileSystem + Send + Sync>,
}

#[async_trait]
impl NFSFileSystemExtended for DefaultNFSFileSystemExtended {

    /// Returns the set of capabilities supported
    fn capabilities(&self) -> VFSCapabilities {
        self.vfs.capabilities()
    }


    /// Returns the ID the of the root directory "/"
    fn root_dir(&self) -> fileid3 {
        self.vfs.root_dir()
    }

    /// Look up the id of a path in a directory
    ///
    /// i.e. given a directory dir/ containing a file a.txt
    /// this may call lookup(id_of("dir/"), "a.txt")
    /// and this should return the id of the file "dir/a.txt"
    ///
    /// This method should be fast as it is used very frequently.
    async fn lookup(&self, dirid: fileid3, filename: &filename3, _user_ctx : &UserContext,
        dir_attr : &mut post_op_attr, obj_attr : &mut post_op_attr) -> Result<fileid3, nfsstat3> {

        *dir_attr = match self.vfs.getattr(dirid).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };
        let result = self.vfs.lookup(dirid, filename).await;
        match result {
            Ok(fid) => {
                *obj_attr = match self.vfs.getattr(fid).await {
                    Ok(v) => post_op_attr::attributes(v),
                    Err(_) => post_op_attr::Void,
                };
            }
            Err(_) => {
            }
        }
        result
    }

    /// Returns the attributes of an id.
    /// This method should be fast as it is used very frequently.
    async fn getattr(&self, id: fileid3, _user_ctx : &UserContext) -> Result<fattr3, nfsstat3> {
        self.vfs.getattr(id).await
    }

    /// Sets the attributes of an id
    /// this should return Err(nfsstat3::NFS3ERR_ROFS) if readonly
    async fn setattr(&self, id: fileid3, setattr: sattr3, _user_ctx : &UserContext) -> Result<fattr3, nfsstat3> {
        self.vfs.setattr(id, setattr).await
    }

    async fn access(&self, id: fileid3, access : u32, _user_ctx : &UserContext, obj_attr : &mut post_op_attr) -> Result<u32, nfsstat3> {
        *obj_attr = match self.vfs.getattr(id).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(stat) =>  {
                return Err(stat)
            }
        };

        let mut new_access : u32 = access;
        if !matches!(self.vfs.capabilities(), VFSCapabilities::ReadWrite) {
            new_access &= ACCESS3_READ | ACCESS3_LOOKUP;
        }

        Ok(new_access)
    }


    /// Reads the contents of a file returning (bytes, EOF)
    /// Note that offset/count may go past the end of the file and that
    /// in that case, all bytes till the end of file are returned.
    /// EOF must be flagged if the end of the file is reached by the read.
    async fn read(&self, id: fileid3, offset: u64, count: u32, _user_ctx : &UserContext, obj_attr : &mut post_op_attr) -> Result<(Vec<u8>, bool), nfsstat3> {
        *obj_attr = match self.vfs.getattr(id).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };
        self.vfs.read(id, offset, count).await
    }

    /// Writes the contents of a file returning (bytes, EOF)
    /// Note that offset/count may go past the end of the file and that
    /// in that case, the file is extended.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn write(&self, id: fileid3, offset: u64, data: &[u8], _user_ctx : &UserContext, obj_attr : &mut pre_op_attr) -> Result<fattr3, nfsstat3> {
        *obj_attr = match self.vfs.getattr(id).await {
            Ok(v) => {
                let wccattr = wcc_attr {
                    size: v.size,
                    mtime: v.mtime,
                    ctime: v.ctime,
                };
                pre_op_attr::attributes(wccattr)
            }
            Err(_) => pre_op_attr::Void,
        };

        self.vfs.write(id, offset, data).await
    }

    /// Creates a file with the following attributes.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn create(
        &self,
        dirid: fileid3,
        filename: &filename3,
        attr: sattr3,
        _user_ctx : &UserContext,
        pre_dir_attr : &mut pre_op_attr,
        post_dir_attr : &mut post_op_attr,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        *pre_dir_attr = match self.vfs.getattr(dirid).await {
            Ok(v) => {
                let wccattr = wcc_attr {
                    size: v.size,
                    mtime: v.mtime,
                    ctime: v.ctime,
                };
                pre_op_attr::attributes(wccattr)
            }
            Err(_) => pre_op_attr::Void,
        };

        let result = self.vfs.create(dirid, filename, attr).await;

        // Re-read dir attributes for post op attr
        *post_dir_attr = match self.vfs.getattr(dirid).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };

        result
    }

    /// Creates a file if it does not already exist
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn create_exclusive(
        &self,
        dirid: fileid3,
        filename: &filename3,
        _user_ctx : &UserContext,
        pre_dir_attr : &mut pre_op_attr,
        post_dir_attr : &mut post_op_attr,
    ) -> Result<fileid3, nfsstat3> {
        *pre_dir_attr = match self.vfs.getattr(dirid).await {
            Ok(v) => {
                let wccattr = wcc_attr {
                    size: v.size,
                    mtime: v.mtime,
                    ctime: v.ctime,
                };
                pre_op_attr::attributes(wccattr)
            }
            Err(stat) =>
                return Err(stat)
        };

        let result = self.vfs.create_exclusive(dirid, filename).await;

        // Re-read dir attributes for post op attr
        *post_dir_attr = match self.vfs.getattr(dirid).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };

        result
    }

    /// Makes a directory with the following attributes.
    /// If not supported dur to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn mkdir(
        &self,
        dirid: fileid3,
        dirname: &filename3,
        _user_ctx : &UserContext,
        pre_dir_attr : &mut pre_op_attr,
        post_dir_attr : &mut post_op_attr,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        // get the object attributes before the write
        *pre_dir_attr = match self.vfs.getattr(dirid).await {
            Ok(v) => {
                let wccattr = wcc_attr {
                    size: v.size,
                    mtime: v.mtime,
                    ctime: v.ctime,
                };
                pre_op_attr::attributes(wccattr)
            }
            Err(stat) => {
                return Err(stat)
            }
        };

        let result = self.vfs.mkdir(dirid, dirname).await;

        // Re-read dir attributes for post op attr
        *post_dir_attr = match self.vfs.getattr(dirid).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };

        result
    }

    /// Removes a file.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn remove(&self, dirid: fileid3, filename: &filename3, _user_ctx : &UserContext, pre_dir_attr : &mut pre_op_attr, post_dir_attr : &mut post_op_attr) -> Result<(), nfsstat3> {
        // get the object attributes before the write
        *pre_dir_attr = match self.vfs.getattr(dirid).await {
            Ok(v) => {
                let wccattr = wcc_attr {
                    size: v.size,
                    mtime: v.mtime,
                    ctime: v.ctime,
                };
                pre_op_attr::attributes(wccattr)
            }
            Err(stat) => {
                return Err(stat)
            }
        };

        let result = self.vfs.remove(dirid, filename).await;

        // Re-read dir attributes for post op attr
        *post_dir_attr = match self.vfs.getattr(dirid).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };

        result
    }

    /// Removes a file.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
       _user_ctx : &UserContext,
        pre_from_dir_attr : &mut pre_op_attr,
        pre_to_dir_attr : &mut pre_op_attr,
        post_from_dir_attr : &mut post_op_attr,
        post_to_dir_attr : &mut post_op_attr,
    ) -> Result<(), nfsstat3> {
        // get the object attributes before the write
        *pre_from_dir_attr = match self.vfs.getattr(from_dirid).await {
            Ok(v) => {
                let wccattr = wcc_attr {
                    size: v.size,
                    mtime: v.mtime,
                    ctime: v.ctime,
                };
                pre_op_attr::attributes(wccattr)
            }
            Err(stat) => {
                return Err(stat)
            }
        };

        // get the object attributes before the write
        *pre_to_dir_attr = match self.vfs.getattr(to_dirid).await {
            Ok(v) => {
                let wccattr = wcc_attr {
                    size: v.size,
                    mtime: v.mtime,
                    ctime: v.ctime,
                };
                pre_op_attr::attributes(wccattr)
            }
            Err(stat) => {
                return Err(stat)
            }
        };

        let result = self.vfs.rename(from_dirid, from_filename, to_dirid, to_filename).await;

        // Re-read dir attributes for post op attr
        *post_from_dir_attr = match self.vfs.getattr(from_dirid).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };
        *post_to_dir_attr = match self.vfs.getattr(to_dirid,).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };

        result
    }

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
        _user_ctx : &UserContext,
    ) -> Result<ReadDirResult, nfsstat3> {
        self.vfs.readdir(dirid, start_after, max_entries).await
    }

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
        _user_ctx : &UserContext,
        pre_obj_attr : &mut pre_op_attr,
        post_obj_attr : &mut post_op_attr,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        // get the object attributes before
        *pre_obj_attr = match self.vfs.getattr(dirid).await {
            Ok(v) => {
                let wccattr = wcc_attr {
                    size: v.size,
                    mtime: v.mtime,
                    ctime: v.ctime,
                };
                pre_op_attr::attributes(wccattr)
            }
            Err(stat) => {
                return Err(stat)
            }
        };

        let result = self.vfs.symlink(dirid, linkname, symlink, attr).await;

        // Re-read dir attributes for post op attr
        *post_obj_attr = match self.vfs.getattr(dirid).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(_) => post_op_attr::Void,
        };

        result
    }

    /// Reads a symlink
    async fn readlink(&self, id: fileid3, _user_ctx : &UserContext, symlink_attr : &mut post_op_attr) -> Result<nfspath3, nfsstat3> {
        *symlink_attr = match self.vfs.getattr(id).await {
            Ok(v) => post_op_attr::attributes(v),
            Err(stat) => {
                return Err(stat)
            }
        };
        self.vfs.readlink(id).await
    }

    /// Get static file system Information
    async fn fsinfo(
        &self,
        root_fileid: fileid3,
        _user_ctx: &UserContext,
    ) -> Result<fsinfo3, nfsstat3> {
        self.vfs.fsinfo(root_fileid).await
    }

    /// Converts the fileid to an opaque NFS file handle. Optional.
    fn id_to_fh(&self, id: fileid3) -> nfs_fh3 {
        self.vfs.id_to_fh(id)
    }

    /// Converts an opaque NFS file handle to a fileid.  Optional.
    fn fh_to_id(&self, id: &nfs_fh3) -> Result<fileid3, nfsstat3> {
        self.vfs.fh_to_id(id)
    }
    /// Converts a complete path to a fileid.  Optional.
    /// The default implementation walks the directory structure with lookup()
    async fn path_to_id(&self, path: &[u8]) -> Result<fileid3, nfsstat3> {
        self.vfs.path_to_id(path).await
    }

    fn serverid(&self) -> cookieverf3 {
        self.vfs.serverid()
    }
}

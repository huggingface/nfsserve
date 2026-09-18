use std::cmp::Ordering;
use std::sync::Once;
use std::time::SystemTime;

use async_trait::async_trait;

use crate::nfs;
use crate::nfs::*;
#[derive(Default, Debug)]
pub struct DirEntrySimple {
    pub fileid: fileid3,
    pub name: filename3,
    /// Pagination cookie; see [`DirEntry::cookie`].
    pub cookie: u64,
}
#[derive(Default, Debug)]
pub struct ReadDirSimpleResult {
    pub entries: Vec<DirEntrySimple>,
    pub end: bool,
}

#[derive(Default, Debug)]
pub struct DirEntry {
    pub fileid: fileid3,
    pub name: filename3,
    pub attr: fattr3,
    /// Pagination cookie for this entry, echoed back by the client in the next
    /// `readdir` as `start_after`.
    ///
    /// This used to be the `fileid`, which cannot work in general: a fileid is not
    /// unique within a directory. Hard links share one, and so do `.` and `..` in a
    /// file system's root. When the server truncates a reply to its byte budget the
    /// client resumes from the last entry it actually received, so an ambiguous
    /// cookie either rewinds the listing or skips the entries in between — silently,
    /// with eof set. RFC 1813 §3.3.16 makes the cookie server-opaque precisely so an
    /// implementation can use a position instead of an identity.
    ///
    /// Set it to anything that uniquely identifies the entry's position in the
    /// listing; an index is the obvious choice. Zero is reserved: the client sends
    /// cookie 0 to mean "start at the beginning".
    pub cookie: u64,
}
#[derive(Default, Debug)]
pub struct ReadDirResult {
    pub entries: Vec<DirEntry>,
    pub end: bool,
}

impl ReadDirSimpleResult {
    fn from_readdir_result(result: &ReadDirResult) -> ReadDirSimpleResult {
        let entries: Vec<DirEntrySimple> = result
            .entries
            .iter()
            .map(|e| DirEntrySimple {
                fileid: e.fileid,
                name: e.name.clone(),
                cookie: e.cookie,
            })
            .collect();
        ReadDirSimpleResult {
            entries,
            end: result.end,
        }
    }
}

static mut GENERATION_NUMBER: u64 = 0;
static GENERATION_NUMBER_INIT: Once = Once::new();

fn get_generation_number() -> u64 {
    unsafe {
        GENERATION_NUMBER_INIT.call_once(|| {
            GENERATION_NUMBER = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        });
        GENERATION_NUMBER
    }
}

/// What capabilities are supported
pub enum VFSCapabilities {
    ReadOnly,
    ReadWrite,
}

/// Dynamic file system statistics, as reported by the NFS `FSSTAT` procedure.
///
/// These are the numbers a client shows for `df`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsStat {
    /// Total size of the file system, in bytes.
    pub total_bytes: u64,
    /// Free space, in bytes.
    pub free_bytes: u64,
    /// Free space available to the user the request is made on behalf of, in bytes. For a read-only
    /// file system this is normally zero.
    pub available_bytes: u64,
    /// Total number of file slots.
    pub total_files: u64,
    /// Number of free file slots.
    pub free_files: u64,
    /// Number of free file slots available to the user the request is made on behalf of.
    pub available_files: u64,
    /// Number of seconds for which the file system is not expected to change, per RFC 1813
    /// §3.3.18: zero for a volatile file system, and "for an immutable file system, such as a
    /// CD-ROM, this would be the largest unsigned integer" — so `u32::MAX` advertises that the
    /// file system does not change, which is what a read-only export wants.
    pub invar_sec: u32,
}

impl Default for FsStat {
    /// The placeholder values the server reported before [`NFSFileSystem::fsstat`] existed: 1 TiB
    /// of space and 1 Gi file slots, all of it free, and an `invar_sec` claiming the file system
    /// never changes.
    fn default() -> Self {
        const TIB: u64 = 1024 * 1024 * 1024 * 1024;
        const GI: u64 = 1024 * 1024 * 1024;
        Self {
            total_bytes: TIB,
            free_bytes: TIB,
            available_bytes: TIB,
            total_files: GI,
            free_files: GI,
            available_files: GI,
            invar_sec: u32::MAX,
        }
    }
}

/// The basic API to implement to provide an NFS file system
///
/// Opaque FH
/// ---------
/// Files are only uniquely identified by a 64-bit file id. (basically an inode number)
/// We automatically produce internally the opaque filehandle which is comprised of
///  - A 64-bit generation number derived from the server startup time
///   (i.e. so the opaque file handle expires when the NFS server restarts)
///  - The 64-bit file id
//
/// readdir pagination
/// ------------------
/// We do not use cookie verifier. We just use the start_after.  The
/// implementation should allow startat to start at any position. That is,
/// the next query to readdir may be the last entry in the previous readdir
/// response.
//
/// There is a wierd annoying thing about readdir that limits the number
/// of bytes in the response (instead of the number of entries). The caller
/// will have to truncate the readdir response / issue more calls to readdir
/// accordingly to fill up the expected number of bytes without exceeding it.
//
/// Other requirements
/// ------------------
///  getattr needs to be fast. NFS uses that a lot
//
///  The 0 fileid is reserved and should not be used
#[async_trait]
pub trait NFSFileSystem: Sync {
    /// Returns the set of capabilities supported
    fn capabilities(&self) -> VFSCapabilities;
    /// Returns the ID the of the root directory "/"
    fn root_dir(&self) -> fileid3;
    /// Look up the id of a path in a directory
    ///
    /// i.e. given a directory dir/ containing a file a.txt
    /// this may call lookup(id_of("dir/"), "a.txt")
    /// and this should return the id of the file "dir/a.txt"
    ///
    /// This method should be fast as it is used very frequently.
    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3>;

    /// Returns the attributes of an id.
    /// This method should be fast as it is used very frequently.
    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3>;

    /// Sets the attributes of an id
    /// this should return Err(nfsstat3::NFS3ERR_ROFS) if readonly
    async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3>;

    /// Reads the contents of a file returning (bytes, EOF)
    /// Note that offset/count may go past the end of the file and that
    /// in that case, all bytes till the end of file are returned.
    /// EOF must be flagged if the end of the file is reached by the read.
    async fn read(&self, id: fileid3, offset: u64, count: u32) -> Result<(Vec<u8>, bool), nfsstat3>;

    /// Writes the contents of a file returning (bytes, EOF)
    /// Note that offset/count may go past the end of the file and that
    /// in that case, the file is extended.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn write(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3>;

    /// Creates a file with the following attributes.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn create(&self, dirid: fileid3, filename: &filename3, attr: sattr3) -> Result<(fileid3, fattr3), nfsstat3>;

    /// Creates a file if it does not already exist
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn create_exclusive(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3>;

    /// Makes a directory with the following attributes.
    /// If not supported dur to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn mkdir(&self, dirid: fileid3, dirname: &filename3) -> Result<(fileid3, fattr3), nfsstat3>;

    /// Removes a file.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3>;

    /// Renames a file.
    /// If not supported due to readonly file system
    /// this should return Err(nfsstat3::NFS3ERR_ROFS)
    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
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
    ) -> Result<ReadDirResult, nfsstat3>;

    /// Simple version of readdir.
    /// Only need to return filename and id
    async fn readdir_simple(&self, dirid: fileid3, count: usize) -> Result<ReadDirSimpleResult, nfsstat3> {
        Ok(ReadDirSimpleResult::from_readdir_result(&self.readdir(dirid, 0, count).await?))
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
    ) -> Result<(fileid3, fattr3), nfsstat3>;

    /// Reads a symlink
    async fn readlink(&self, id: fileid3) -> Result<nfspath3, nfsstat3>;

    /// Get dynamic file system statistics: how much space and how many file slots the file system
    /// has, and how much of that is free. This is what a client reports for `df`.
    ///
    /// The default implementation returns [`FsStat::default`], which is a placeholder claiming 1
    /// TiB of entirely free space. Override it to report the real numbers for the backing store;
    /// otherwise clients will show a wrong capacity, and a read-only file system will appear to
    /// have room to write into.
    async fn fsstat(&self, root_fileid: fileid3) -> Result<FsStat, nfsstat3> {
        let _ = root_fileid;
        Ok(FsStat::default())
    }

    /// Get static file system Information
    async fn fsinfo(&self, root_fileid: fileid3) -> Result<fsinfo3, nfsstat3> {
        let dir_attr: nfs::post_op_attr = match self.getattr(root_fileid).await {
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
    fn id_to_fh(&self, id: fileid3) -> nfs_fh3 {
        let gennum = get_generation_number();
        let mut ret: Vec<u8> = Vec::new();
        ret.extend_from_slice(&gennum.to_le_bytes());
        ret.extend_from_slice(&id.to_le_bytes());
        nfs_fh3 { data: ret }
    }
    /// Converts an opaque NFS file handle to a fileid.  Optional.
    fn fh_to_id(&self, id: &nfs_fh3) -> Result<fileid3, nfsstat3> {
        if id.data.len() != 16 {
            return Err(nfsstat3::NFS3ERR_BADHANDLE);
        }
        let gen = u64::from_le_bytes(id.data[0..8].try_into().unwrap());
        let id = u64::from_le_bytes(id.data[8..16].try_into().unwrap());
        let gennum = get_generation_number();
        match gen.cmp(&gennum) {
            Ordering::Less => Err(nfsstat3::NFS3ERR_STALE),
            Ordering::Greater => Err(nfsstat3::NFS3ERR_BADHANDLE),
            Ordering::Equal => Ok(id),
        }
    }
    /// Converts a complete path to a fileid.  Optional.
    /// The default implementation walks the directory structure with lookup()
    async fn path_to_id(&self, path: &[u8]) -> Result<fileid3, nfsstat3> {
        let splits = path.split(|&r| r == b'/');
        let mut fid = self.root_dir();
        for component in splits {
            if component.is_empty() {
                continue;
            }
            fid = self.lookup(fid, &component.into()).await?;
        }
        Ok(fid)
    }

    fn serverid(&self) -> cookieverf3 {
        let gennum = get_generation_number();
        gennum.to_le_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default must keep reporting exactly what the server hardcoded before `fsstat` became
    /// overridable, so that existing implementations of [`NFSFileSystem`] see no behaviour change.
    #[test]
    fn fsstat_default_matches_previous_hardcoded_values() {
        let stat = FsStat::default();
        assert_eq!(stat.total_bytes, 1024 * 1024 * 1024 * 1024);
        assert_eq!(stat.free_bytes, 1024 * 1024 * 1024 * 1024);
        assert_eq!(stat.available_bytes, 1024 * 1024 * 1024 * 1024);
        assert_eq!(stat.total_files, 1024 * 1024 * 1024);
        assert_eq!(stat.free_files, 1024 * 1024 * 1024);
        assert_eq!(stat.available_files, 1024 * 1024 * 1024);
        assert_eq!(stat.invar_sec, u32::MAX);
    }
}

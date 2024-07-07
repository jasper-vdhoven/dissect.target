from typing import Any, Optional, Generator, BinaryIO, Iterator
from enum import Enum

from flow.record import Record
from dissect.cstruct import cstruct
from dissect.cstruct.utils import p32, hexdump
from dissect.target import plugin, Target
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.exceptions import UnsupportedPluginError, FilesystemError

c_aurecord_def = """
/*
 * Structs pulled from https://github.com/openbsm/openbsm/blob/54a0c07cf8bac71554130e8f6760ca68e5f36c7f/bsm/libbsm.h
 * Types changed from u_int8_t / u_int16_t / u_int32_t -> uint8_t / uint16_t / uint32_t / etc to match types with Dissect.cstruct
 */

typedef struct au_tid32 {
    uint32_t    port;
    uint32_t    addr;
} au_tid32_t;

typedef struct au_tid64 {
    uint64_t    port;
    uint32_t    addr;
} au_tid64_t;

typedef struct au_tidaddr32 {
    uint32_t    port;
    uint32_t    type;
    uint32_t    addr[type / 4];
} au_tidaddr32_t;

typedef struct au_tidaddr64 {
    uint64_t    port;
    uint32_t    type;
    uint32_t    addr[4];
} au_tidaddr64_t;

/*
 * argument #              1 byte
 * argument value          4 bytes/8 bytes (32-bit/64-bit value)
 * text length             2 bytes
 * text                    N bytes + 1 terminating NULL byte
 */
typedef struct {
    uchar       no;
    uint32_t    val;
    uint16_t    len;
    // changed type char *text to play nice with Dissect parsing
    char        text[len-1];
    char        nbt;
} au_arg32_t;

typedef struct {
    uchar       no;
    uint64_t    val;
    uint16_t    len;
    // changed type char *text to play nice with Dissect parsing
    char        text[len-1];
    char        nbt;
} au_arg64_t;

/*
 * token ID                1 byte
 * argument #              1 byte
 * uuid                    16 bytes
 * text length             2 bytes
 * text                    N bytes + 1 terminating NULL byte
 */
typedef struct {
    uchar       no;
    uint8_t     uuid[16];
    uint16_t    len;
    char        *text;
} au_arg_uuid_t;

/*
 * how to print            1 byte
 * basic unit              1 byte
 * unit count              1 byte
 * data items              (depends on basic unit)
 */
typedef struct {
 uchar      howtopr;
 uchar      bu;
 uchar      uc;
 uchar      *data;
} au_arb_t;

/*
 * file access mode        4 bytes
 * owner user ID           4 bytes
 * owner group ID          4 bytes
 * file system ID          4 bytes
 * node ID                 8 bytes
 * device                  4 bytes/8 bytes (32-bit/64-bit)
 */
typedef struct {
    uint32_t    mode;
    uint32_t    uid;
    uint32_t    gid;
    uint32_t    fsid;
    uint64_t    nid;
    uint32_t    dev;
} au_attr32_t;

typedef struct {
    uint32_t    mode;
    uint32_t    uid;
    uint32_t    gid;
    uint32_t    fsid;
    uint64_t    nid;
    uint64_t    dev;
} au_attr64_t;

/*
 * count                   4 bytes
 * text                    count null-terminated string(s)
 */
typedef struct {
    uint32_t    count;
    // type is changed from char *text[AUDIT_MAX_ARGS]; to play nice with Dissect parsing
    char        text[count][];
} au_execarg_t;

/*
 * count                   4 bytes
 * text                    count null-terminated string(s)
 */
typedef struct {
    uint32_t    count;
    // type is changed from char *text[AUDIT_MAX_ENV]; to play nice with Dissect parsing
    char		text[count][];
} au_execenv_t;

/*
 * status                  4 bytes
 * return value            4 bytes
 */
typedef struct {
    uint32_t    status;
    uint32_t    ret;
} au_exit_t;

/*
 * seconds of time         4 bytes
 * milliseconds of time    4 bytes
 * file name length        2 bytes
 * file pathname           N bytes + 1 terminating NULL byte
 */
typedef struct {
    uint32_t    s;
    uint32_t    ms;
    uint16_t    len;
    char        *name;
} au_file_t;


/*
 * number groups           2 bytes
 * group list              N * 4 bytes
 */
typedef struct {
    uint16_t	no;
    // type is changed from u_int32_t list[AUDIT_MAX_GROUPS] to play nice with Dissect parsing
    uint32_t	list[no][];
} au_groups_t;

/*
 * record byte count       4 bytes
 * version #               1 byte    [2]
 * event type              2 bytes
 * event modifier          2 bytes
 * seconds of time         4 bytes/8 bytes (32-bit/64-bit value)
 * milliseconds of time    4 bytes/8 bytes (32-bit/64-bit value)
 */
typedef struct {
    uint32_t	size;
    uchar		version;
    uint16_t	e_type;
    uint16_t	e_mod;
    uint32_t	s;
    uint32_t	ms;
} au_header32_t;

/*
 * record byte count       4 bytes
 * version #               1 byte     [2]
 * event type              2 bytes
 * event modifier          2 bytes
 * address type/length     1 byte (XXX: actually, 4 bytes)
 * machine address         4 bytes/16 bytes (IPv4/IPv6 address)
 * seconds of time         4 bytes/8 bytes  (32/64-bits)
 * nanoseconds of time     4 bytes/8 bytes  (32/64-bits)
 */
typedef struct {
    uint32_t	size;
    uchar		version;
    uint16_t	e_type;
    uint16_t	e_mod;
    uint32_t	ad_type;
    uint32_t	addr[4];
    uint32_t	s;
    uint32_t	ms;
} au_header32_ex_t;

typedef struct {
    uint32_t	size;
    uchar		version;
    uint16_t	e_type;
    uint16_t	e_mod;
    uint64_t	s;
    uint64_t	ms;
} au_header64_t;

typedef struct {
    uint32_t	size;
    uchar		version;
    uint16_t	e_type;
    uint16_t	e_mod;
    uint32_t	ad_type;
    uint32_t	addr[4];
    uint64_t	s;
    uint64_t	ms;
} au_header64_ex_t;

/*
 * internet address        4 bytes
 */
typedef struct {
    uint32_t    addr;
} au_inaddr_t;

/*
 * type                    4 bytes
 * internet address        16 bytes
 */
typedef struct {
    uint32_t	type;
    uint32_t	addr[4];
} au_inaddr_ex_t;

/*
 * version and ihl         1 byte
 * type of service         1 byte
 * length                  2 bytes
 * id                      2 bytes
 * offset                  2 bytes
 * ttl                     1 byte
 * protocol                1 byte
 * checksum                2 bytes
 * source address          4 bytes
 * destination address     4 bytes
 */
typedef struct {
    uchar		version;
    uchar		tos;
    uint16_t	len;
    uint16_t	id;
    uint16_t	offset;
    uchar		ttl;
    uchar		prot;
    uint16_t	chksm;
    uint32_t	src;
    uint32_t	dest;
} au_ip_t;

/*
 * object ID type          1 byte
 * object ID               4 bytes
 */
typedef struct {
    uchar		type;
    uint32_t	id;
} au_ipc_t;

/*
 * owner user ID           4 bytes
 * owner group ID          4 bytes
 * creator user ID         4 bytes
 * creator group ID        4 bytes
 * access mode             4 bytes
 * slot sequence #         4 bytes
 * key                     4 bytes
 */
typedef struct {
    uint32_t	uid;
    uint32_t	gid;
    uint32_t	puid;
    uint32_t	pgid;
    uint32_t	mode;
    uint32_t	seq;
    uint32_t	key;
} au_ipcperm_t;

/*
 * port IP address         2 bytes
 */
typedef struct {
    uint16_t	port;
} au_iport_t;

/*
 * length		2 bytes
 * data			length bytes
 */
typedef struct {
    uint16_t	 size;
    // changed type from char *data to play nice with Dissect parsing
    char         data[size-1];
    char         nbt;
} au_opaque_t;

/*
 * path length             2 bytes
 * path                    N bytes + 1 terminating NULL byte
 */
typedef struct {
    uint16_t	 len;
    // changed type char *path to play nice with Dissect parsing
    char         path[len-1];
    char         nbt;
} au_path_t;

/*
 * audit ID                4 bytes
 * effective user ID       4 bytes
 * effective group ID      4 bytes
 * real user ID            4 bytes
 * real group ID           4 bytes
 * process ID              4 bytes
 * session ID              4 bytes
 * terminal ID
 * port ID               4 bytes/8 bytes (32-bit/64-bit value)
 * machine address       4 bytes
 */
typedef struct {
    uint32_t	auid;
    uint32_t	euid;
    uint32_t	egid;
    uint32_t	ruid;
    uint32_t	rgid;
    uint32_t	pid;
    uint32_t	sid;
    // commented out to aid printing struct au_tid32_t tid;
    uint32_t	tid_port;
    uint32_t	tid_addr;
} au_proc32_t;

typedef struct {
    uint32_t	auid;
    uint32_t	euid;
    uint32_t	egid;
    uint32_t	ruid;
    uint32_t	rgid;
    uint32_t	pid;
    uint32_t	sid;
    // commented out to aid printing struct au_tid64_t tid;
    uint64_t	tid_port;
    uint32_t	tid_addr;
} au_proc64_t;

/*
 * audit ID                4 bytes
 * effective user ID       4 bytes
 * effective group ID      4 bytes
 * real user ID            4 bytes
 * real group ID           4 bytes
 * process ID              4 bytes
 * session ID              4 bytes
 * terminal ID
 * port ID               4 bytes/8 bytes (32-bit/64-bit value)
 * type                  4 bytes
 * machine address       16 bytes
 */
typedef struct {
    uint32_t	    auid;
    uint32_t	    euid;
    uint32_t	    egid;
    uint32_t	    ruid;
    uint32_t	    rgid;
    uint32_t	    pid;
    uint32_t	    sid;
    au_tidaddr32_t	tid;
} au_proc32ex_t;

typedef struct {
    uint32_t        auid;
    uint32_t        euid;
    uint32_t        egid;
    uint32_t        ruid;
    uint32_t        rgid;
    uint32_t        pid;
    uint32_t        sid;
    au_tidaddr64_t	tid;
} au_proc64ex_t;

/*
 * error status            1 byte
 * return value            4 bytes/8 bytes (32-bit/64-bit value)
 */
typedef struct {
    uchar		status;
    uint32_t	ret;
} au_ret32_t;

typedef struct {
    uchar		err;
    uint64_t	val;
} au_ret64_t;

/*
 * token ID                1 byte
 * return value #          1 byte
 * uuid                    16 bytes
 * text length             2 bytes
 * text                    N bytes + 1 terminating NULL byte
 */
typedef struct {
    uchar		no;
    uint8_t	    uuid[16];
    uint16_t	len;
    char		*text;
} au_ret_uuid_t;

/*
 * sequence number         4 bytes
 */
typedef struct {
    uint32_t	seqno;
} au_seq_t;

/*
 * socket type             2 bytes
 * local port              2 bytes
 * local Internet address  4 bytes
 * remote port             2 bytes
 * remote Internet address 4 bytes
 */
typedef struct {
    uint16_t	type;
    uint16_t	l_port;
    uint32_t	l_addr;
    uint16_t	r_port;
    uint32_t	r_addr;
} au_socket_t;

// OpenBSM source code lists wrong comment
// struct def taken from: https://github.com/apple/darwin-xnu/blob/8f02f2a044b9bb1ad951987ef5bab20ec9486310/bsd/security/audit/audit_bsm_token.c#L803
/*
 * socket domain	2 bytes
 * socket type		2 bytes
 * address type		2 bytes
 * local port		2 bytes
 * local address	4 bytes/16 bytes (IPv4/IPv6 address)
 * remote port		2 bytes
 * remote address	4 bytes/16 bytes (IPv4/IPv6 address)
 */
typedef struct {
    uint16_t	domain;
    uint16_t	type;
    uint16_t	atype;
    uint16_t	l_port;
    uint8_t	    l_addr[atype];
    uint16_t	r_port;
    uint8_t	    r_addr[atype];
} au_socket_ex_t;

/*
 * socket family           2 bytes
 * local port              2 bytes
 * socket address          4 bytes/16 bytes (IPv4/IPv6 address)
 */
typedef struct {
    uint16_t	family;
    uint16_t	port;
    uint32_t	addr[4];
} au_socketinet_ex32_t;

typedef struct {
    uint16_t	family;
    uint16_t	port;
    uint32_t	addr;
} au_socketinet32_t;

/*
 * socket family           2 bytes
 * path                    104 bytes
 */
typedef struct {
    uint16_t	family;
    char		path[104];
} au_socketunix_t;

/*
 * audit ID                4 bytes
 * effective user ID       4 bytes
 * effective group ID      4 bytes
 * real user ID            4 bytes
 * real group ID           4 bytes
 * process ID              4 bytes
 * session ID              4 bytes
 * terminal ID
 * 	port ID               4 bytes/8 bytes (32-bit/64-bit value)
 * 	machine address       4 bytes
 */
typedef struct {
    uint32_t	auid;
    uint32_t	euid;
    uint32_t	egid;
    uint32_t	ruid;
    uint32_t	rgid;
    uint32_t	pid;
    uint32_t	sid;
    // commented out to aid displaying struct au_tid32_t tid;
    uint32_t	tid_port;
    uint32_t	tid_addr;
} au_subject32_t;

typedef struct {
    uint32_t	auid;
    uint32_t	euid;
    uint32_t	egid;
    uint32_t	ruid;
    uint32_t	rgid;
    uint32_t	pid;
    uint32_t	sid;
    // commented out to aid printing struct au_tid64_t tid;
    uint64_t	tid_port;
    uint32_t	tid_addr;
} au_subject64_t;

/*
 * audit ID                4 bytes
 * effective user ID       4 bytes
 * effective group ID      4 bytes
 * real user ID            4 bytes
 * real group ID           4 bytes
 * process ID              4 bytes
 * session ID              4 bytes
 * terminal ID
 * port ID               4 bytes/8 bytes (32-bit/64-bit value)
 * type                  4 bytes
 * machine address       16 bytes
 */
typedef struct {
    uint32_t	auid;
    uint32_t	euid;
    uint32_t	egid;
    uint32_t	ruid;
    uint32_t	rgid;
    uint32_t	pid;
    uint32_t	sid;
    // commented out to aid printing struct au_tidaddr32_t tid;
    uint32_t	port;
    uint32_t	type;
    uint32_t	addr[type / 4];
} au_subject32ex_t;

typedef struct {
    uint32_t	auid;
    uint32_t	euid;
    uint32_t	egid;
    uint32_t	ruid;
    uint32_t	rgid;
    uint32_t	pid;
    uint32_t	sid;
    // commented out to aid printing struct au_tidaddr64_t tid;
    uint64_t	port;
    uint32_t	type;
    uint32_t	addr[4];
} au_subject64ex_t;

/*
 * text length             2 bytes
 * text                    N bytes + 1 terminating NULL byte
 */
typedef struct {
    uint16_t    len;
    // changed type from char *text to play nice with dissect parsing
    char        text[len-1];
    char        nbt;
} au_text_t;

/*
 * upriv status         1 byte
 * privstr len          2 bytes
 * privstr              N bytes + 1 (0x00 byte)
*/
typedef struct {
    uint8_t     sorf;
    uint16_t    privstrlen;
    // changed type char *priv to play nice with Dissect parsing
    char        priv[privstrlen-1];
    char        nbt;
} au_priv_t;

/*
* privset
* privtstrlen		2 bytes
* privtstr		N Bytes + 1
* privstrlen		2 bytes
* privstr		N Bytes + 1
*/
typedef struct {
    uint16_t	privtstrlen;
    char        *privtstr;
    uint16_t	privstrlen;
    char		*privstr;
} au_privset_t;

/*
 * zonename length	2 bytes
 * zonename text	N bytes + 1 NULL terminator
 */
typedef struct {
    uint16_t    len;
    // changed type char *zonename to play nice with Dissect parsing
    char        zonename[len-1];
    char        nbt;
} au_zonename_t;

typedef struct {
    uint32_t	ident;
    uint16_t	filter;
    uint16_t	flags;
    uint32_t	fflags;
    uint32_t	data;
} au_kevent_t;

typedef struct {
    uint16_t   length;
    // changed type char *data to play nice with Dissect parsing
    char       data[length-1];
    char       nbt;
} auinvalid_t;

/*
 * trailer magic number    2 bytes
 * record byte count       4 bytes
 */
typedef struct {
    uint16_t	magic;
    uint32_t	count;
} au_trailer_t;

/*
 * socket family           2 bytes
 * path                    (up to) 104 bytes + NULL  (NULL terminated string)
 */
typedef struct {
    ushort      family;
    char        path[];
} au_unixsock_t;

// macOS specific struct pulled from darwin-xnu source code at:
// https://github.com/apple/darwin-xnu/blob/8f02f2a044b9bb1ad951987ef5bab20ec9486310/bsd/security/audit/audit_private.h#L206
/*
 * signer type          4 bytes
 * signer id length     2 bytes
 * signer id            n bytes
 * signer id truncated  1 byte
 * team id length       2 bytes
 * team id              n bytes
 * team id truncated    1 byte
 * cdhash length        2 bytes
 * cdhash               n bytes
 */
struct au_identity_info {
    uint32_t        signer_type;
    short           signer_id_length;
    char            signing_id[signer_id_length-1];
    char            nbt_1;
    uchar           signing_id_trunc;
    short           team_id_length;
    char            team_id[team_id_length-1];
    char            nbt_2;
    uchar           team_id_trunc;
    short           cdhash_length;
    char            cdhash[cdhash_length];
};

// Struct def pulled from: https://github.com/apple/darwin-xnu/blob/8f02f2a044b9bb1ad951987ef5bab20ec9486310/bsd/security/audit/audit_bsm_token.c#L921
/*
 * socket family           2 bytes
 * local port              2 bytes
 * socket address          16 bytes
 */
typedef struct {
    short           socket_family;
    ushort          l_port;
    uint8_t         addr[16];
} au_socketinet128_t;

// Struct def pulled from: https://github.com/apple/darwin-xnu/blob/8f02f2a044b9bb1ad951987ef5bab20ec9486310/bsd/security/audit/audit_bsm_token.c#L229
/*
 * how to print            1 byte
 * basic unit              1 byte
 * unit count              1 byte
 * data items headerheader             (depends on basic unit)
 */
typedef struct {
    uint8_t         htprint;
    uint8_t         butype;
    uint8_t         unit_count;
    // thx again Yoran
    uint8_t         data_items[unit_count * 1 << butype];
} au_data_t;
"""

c_aurecord = cstruct(endian=">")
c_aurecord.load(c_aurecord_def, compiled=True)


class RecordMagic(Enum):
    AU_INVALID_T = 00
    AU_TRAILER_T = 19
    AU_HEADER32_T = 20
    AU_HEADER32_EX_T = 21
    AU_DATA_T = 33
    AU_IPC_T = 34
    AU_PATH_T = 35
    AU_SUBJECT32_T = 36
    AU_PROC32_T = 38
    AU_RET32_T = 39
    AU_TEXT_T = 40
    AU_OPAQUE_T = 41
    AU_INADDR_T = 42
    AU_IP_T = 43
    AU_IPORT_T = 44
    AU_ARG32_T = 45
    AU_SOCKET_T = 46
    AU_SEQ_T = 47
    AU_IPCPERM_T = 50
    AU_GROUPS_T = 52
    AU_EXECARG_T = 60
    AU_EXECENV_T = 61
    AU_ATTR32_t = 62
    AU_EXIT_T = 82
    AU_ARG64_T = 113
    AU_RET64_t = 114
    AU_ATTR64_T = 115
    AU_HEADER64_T = 116
    AU_SUBJECT64_T = 117
    AU_PROCESS64_T = 119
    AU_HEADER64_EXT_T = 121
    AU_SUBJECT32EX_T = 122
    AU_PROC32EX_T = 123
    AU_SUBJECT64EX_T = 124
    AU_PROCESS64EX_T = 125
    AU_INADDR_EX_T = 126
    AU_SOCKETEX32_T = 127
    AU_SOCKETINET32_T = 128
    AU_SOCKETINET128_T = 129
    AU_UNIXSOCK_T = 130
    AU_IDENTITY_INFO = 237


# TODO: add Solaris parsing support

OpenBSMRecord = TargetRecordDescriptor(
    "unix/log/openbsm", [("datetime", "ts"), ("varint", "ms"), ("string", "message"), ("string", "type")]
)


class OpenBSMPlugin(plugin.Plugin):
    """Plugin for fetching and parsing OpenBSM audit trails"""

    RECORD_NAME = "filesystem/unix/openbsm"
    LOGS_DIR_PATH = "/var/audit"
    GLOB = "*[!current]"  # current is a symlink to *.not_terminated

    def __init__(self, target):
        super().__init__(target)

    def check_compatible(self) -> None:
        if not self.target.fs.path(self.LOGS_DIR_PATH).exists():
            raise UnsupportedPluginError("No OpenBSM files found")

    @plugin.export(record=DynamicDescriptor(["datetime"]))
    def openbsm(self):
        for file in self.target.fs.path(self.LOGS_DIR_PATH).glob(self.GLOB):
            if not file.exists():
                self.target.log.warning(f"Audit trail log file does not exist: {file}")

            self.target.log.info(f"Going to parse file: {file}")
            try:
                file_data = file.open()
            except FilesystemError:
                self.target.log.exception(f"Failed to open audit trail: {file}")
                continue

            audit_trail = OpenBSM(file_data, self.target)

            for entry in audit_trail:
                self.target.log.info(f"Event: {entry}")
                yield OpenBSMRecord(
                    ts=entry.get("ts"),
                    ms=entry.get("ms"),
                    type=entry.get("type"),
                    message=entry.get("message"),
                    _target=self.target,
                )

            self.target.log.info("End")


class OpenBSM:
    def __init__(self, fh: BinaryIO, target: Target) -> None:
        fh.seek(0)
        self.fh = fh
        self.target = target

    def __iter__(self) -> Iterator:
        try:
            while True:
                date = None
                ms = None
                reclen, buf = self._fetch_check_header()
                if reclen == 0:
                    break
                bytes_read = 0
                while bytes_read < reclen:
                    record = {
                        "ts": date,
                        "ms": ms,
                        "type": "",
                        "message": "",
                    }
                    match buf[bytes_read]:
                        case RecordMagic.AU_TRAILER_T.value:
                            trailer_t = c_aurecord.au_trailer_t(buf[bytes_read + 1 :])
                            # sizeof au_trailer_t + 1 extra byte to go to the next struct
                            bytes_read += 7
                            record["type"] = "trailer"
                            for field in trailer_t.fields:
                                record["message"] += f"{field}={trailer_t[field]} "
                            yield record
                        case RecordMagic.AU_HEADER32_T.value:
                            header32_t = c_aurecord.au_header32_t(buf[bytes_read + 1 :])
                            # sizeof au_header32_t + 1 extra byte to go to the next struct
                            bytes_read += 18
                            date = int(str(header32_t.s) + str(header32_t.ms))
                            ms = header32_t.ms
                            record["ts"] = date
                            record["ms"] = ms
                            record["type"] = "header32"
                            for field in header32_t.fields:
                                record["message"] += f"{field}={header32_t[field]} "
                            yield record
                        case RecordMagic.AU_HEADER32_EX_T.value:
                            header32ex_t = c_aurecord.au_header32_ex_t(buf[bytes_read + 1 :])
                            bytes_read += 38
                            record["type"] = "header32ex"
                            for field in header32ex_t.fields:
                                record["message"] += f"{field}={header32ex_t[field]} "
                            yield record
                        case RecordMagic.AU_DATA_T.value:
                            data_t = c_aurecord.au_data_t(buf[bytes_read + 1 :])
                            bytes_read += 4 + data_t._sizes["data_items"]
                            record["type"] = "data"
                            for field in data_t.fields:
                                record["message"] += f"{field}={data_t[field]} "
                            yield record
                        case RecordMagic.AU_IPC_T.value:
                            ipc_t = c_aurecord.au_ipc_t(buf[bytes_read + 1 :])
                            bytes_read += 6
                            record["type"] = "ipc"
                            for field in data_t.fields:
                                record["message"] += f"{field}={ipc_t[field]} "
                            yield record
                        case RecordMagic.AU_PATH_T.value:
                            path_t = c_aurecord.au_path_t(buf[bytes_read + 1 :])
                            # sizeof au_path_t + 1 extra byte to go to the next struct
                            bytes_read += 3 + path_t.len
                            record["type"] = "path"
                            for field in path_t.fields:
                                record["message"] += f"{field}={path_t[field]} "
                            yield record
                        case RecordMagic.AU_SUBJECT32_T.value:
                            subject32_t = c_aurecord.au_subject32_t(buf[bytes_read + 1 :])
                            # sizeof au_subject32_t + 1 extra byte to go to the next struct
                            bytes_read += 37
                            record["type"] = "subject32"
                            for field in subject32_t.fields:
                                record["message"] += f"{field}={subject32_t[field]} "
                            yield record
                        case RecordMagic.AU_PROC32_T.value:
                            proc32_t = c_aurecord.au_proc32_t(buf[bytes_read + 1 :])
                            bytes_read += 37
                            record["type"] = "proc32"
                            for field in proc32_t.fields:
                                record["message"] += f"{field}={proc32_t[field]} "
                            yield record
                        case RecordMagic.AU_RET32_T.value:
                            ret32_t = c_aurecord.au_ret32_t(buf[bytes_read + 1 :])
                            # sizeof au_ret32_t + 1 extra byte to go to the next struct
                            bytes_read += 6
                            record["type"] = "ret32"
                            for field in ret32_t.fields:
                                record["message"] += f"{field}={ret32_t[field]} "
                            yield record
                        case RecordMagic.AU_TEXT_T.value:
                            text_t = c_aurecord.au_text_t(buf[bytes_read + 1 :])
                            # sizeof au_text_t + 1 extra byte to go to the next struct
                            bytes_read += text_t.len + 3
                            record["type"] = "text"
                            for field in text_t.fields:
                                record["message"] += f"{field}={text_t[field]} "
                            yield record
                        case RecordMagic.AU_OPAQUE_T.value:
                            opaque_t = c_aurecord.au_opaque_t(buf[bytes_read + 1 :])
                            bytes_read += 4 + opaque_t._sizes["data_items"]
                            record["type"] = "opaque"
                            for field in opaque_t.fields:
                                record["message"] += f"{field}={opaque_t[field]} "
                            yield record
                        case RecordMagic.AU_INADDR_T.value:
                            inaddr_t = c_aurecord.au_inaddr_t(buf[bytes_read + 1 :])
                            bytes_read += 5
                            record["type"] = "inaddr"
                            for field in inaddr_t.fields:
                                record["message"] += f"{field}={inaddr_t[field]} "
                            yield record
                        case RecordMagic.AU_IP_T.value:
                            ip_t = c_aurecord.au_ip_t(buf[bytes_read + 1 :])
                            bytes_read += 21
                            record["type"] = "ip"
                            for field in ip_t.fields:
                                record["message"] += f"{field}={ip_t[field]} "
                            yield record
                        case RecordMagic.AU_IPORT_T.value:
                            iport_t = c_aurecord.au_iport_t(buf[bytes_read + 1 :])
                            bytes_read += 3
                            record["type"] = "iport"
                            for field in iport_t.fields:
                                record["message"] += f"{field}={iport_t[field]} "
                            yield record
                        case RecordMagic.AU_ARG32_T.value:
                            arg32_t = c_aurecord.au_arg32_t(buf[bytes_read + 1 :])
                            # sizeof au_arg32_t + 1 extra byte to go to the next struct
                            bytes_read += arg32_t.len + 8
                            record["type"] = "arg32"
                            for field in arg32_t.fields:
                                record["message"] += f"{field}={arg32_t[field]} "
                            yield record
                        case RecordMagic.AU_SOCKET_T.value:
                            socket_t = c_aurecord.au_socket_t(buf[bytes_read + 1 :])
                            bytes_read += 15
                            record["type"] = "socket"
                            for field in socket_t.fields:
                                record["message"] += f"{field}={socket_t[field]} "
                            yield record
                        case RecordMagic.AU_SEQ_T.value:
                            seq_t = c_aurecord.au_seq_t(buf[bytes_read + 1 :])
                            bytes_read += 5
                            record["type"] = "seq"
                            for field in seq_t.fields:
                                record["message"] += f"{field}={seq_t[field]} "
                            yield record
                        case RecordMagic.AU_IPCPERM_T.value:
                            ipcperm_t = c_aurecord.au_ipcperm_t(buf[bytes_read + 1 :])
                            bytes_read += 29
                            record["type"] = "ipcperm"
                            for field in ipcperm_t.fields:
                                record["message"] += f"{field}={ipcperm_t[field]} "
                            yield record
                        case RecordMagic.AU_EXECARG_T.value:
                            execarg_t = c_aurecord.au_execarg_t(buf[bytes_read + 1 :])
                            """
                                Since we don't know the exact length, iterate over all seperate arguments
                                and add their size to the total count
                            """
                            length = 0
                            for items in execarg_t.text:
                                length += len(items) + 1
                            length += 5
                            bytes_read += length
                            record["type"] = "execarg"
                            for field in execarg_t.fields:
                                record["message"] += f"{field}={execarg_t[field]} "
                            yield record
                        case RecordMagic.AU_EXECENV_T.value:
                            execenv_t = c_aurecord.au_execenv_t(buf[bytes_read + 1 :])
                            length = 0
                            for items in execenv_t.text:
                                length += len(items) + 1
                            length += 5
                            bytes_read += length
                            record["type"] = "execenv"
                            for field in execenv_t.fields:
                                record["message"] += f"{field}={execenv_t[field]} "
                            yield record
                        case RecordMagic.AU_ATTR32_t.value:
                            attr32_t = c_aurecord.au_attr32_t(buf[bytes_read + 1 :])
                            # sizeof au_attr32_t + 1 extra byte to go to the next struct
                            bytes_read += 29
                            record["type"] = "attr32"
                            for field in attr32_t.fields:
                                record["message"] += f"{field}={attr32_t[field]} "
                            yield record
                        case RecordMagic.AU_EXIT_T.value:
                            exit_t = c_aurecord.au_exit_t(buf[bytes_read + 1 :])
                            bytes_read += 9
                            record["type"] = "exit"
                            for field in exit_t.fields:
                                record["message"] += f"{field}={exit_t[field]} "
                            yield record
                        case RecordMagic.AU_ARG64_T.value:
                            arg64_t = c_aurecord.au_arg64_t(buf[bytes_read + 1 :])
                            bytes_read += 12 + arg64_t.len
                            record["type"] = "arg64"
                            for field in arg64_t.fields:
                                record["message"] += f"{field}={arg64_t[field]} "
                            yield record
                        case RecordMagic.AU_RET64_t.value:
                            ret64_t = c_aurecord.au_ret64_t(buf[bytes_read + 1 :])
                            bytes_read += 10
                            record["type"] = "ret64"
                            for field in ret64_t.fields:
                                record["message"] += f"{field}={ret64_t[field]} "
                            yield record
                        case RecordMagic.AU_ATTR64_T.value:
                            attr64_t = c_aurecord.au_attr64_t(buf[bytes_read + 1 :])
                            bytes_read += 33
                            record["type"] = "attr64"
                            for field in attr64_t.fields:
                                record["message"] += f"{field}={attr64_t[field]} "
                            yield record
                        case RecordMagic.AU_HEADER64_T.value:
                            header64_t = c_aurecord.au_header64_t(buf[bytes_read + 1 :])
                            bytes_read += 26
                            record["type"] = "header64"
                            for field in header64_t.fields:
                                record["message"] += f"{field}={header64_t[field]} "
                            yield record
                        case RecordMagic.AU_SUBJECT64_T.value:
                            subject64_t = c_aurecord.au_subject64_t(buf[bytes_read + 1 :])
                            bytes_read += 41
                            record["type"] = "subject64"
                            for field in subject64_t.fields:
                                record["message"] += f"{field}={subject64_t[field]} "
                            yield record
                        case RecordMagic.AU_PROCESS64_T.value:
                            proc64_t = c_aurecord.au_proc64_t(buf[bytes_read + 1 :])
                            bytes_read += 41
                            record["type"] = "proc64"
                            for field in proc64_t.fields:
                                record["message"] += f"{field}={proc64_t[field]} "
                            yield record
                        case RecordMagic.AU_HEADER64_EXT_T.value:
                            header64_ex_t = c_aurecord.au_header64_ex_t(buf[bytes_read + 1 :])
                            bytes_read += 34
                            record["type"] = "header64ex"
                            for field in header64_ex_t.fields:
                                record["message"] += f"{field}={header64_ex_t[field]} "
                            yield record
                        case RecordMagic.AU_SUBJECT32EX_T.value:
                            subject32ex_t = c_aurecord.au_subject32ex_t(buf[bytes_read + 1 :])
                            # sizeof au_subject32ex_t + 1 extra byte to go to the next struct
                            bytes_read += 41
                            record["type"] = "subject32ex"
                            for field in subject32ex_t.fields:
                                record["message"] += f"{field}={subject32ex_t[field]} "
                            yield record
                        case RecordMagic.AU_PROC32EX_T.value:
                            proc32ex_t = c_aurecord.au_proc32ex_t(buf[bytes_read + 1 :])
                            bytes_read += 41
                            record["type"] = "proc32ex"
                            for field in proc32ex_t.fields:
                                record["message"] += f"{field}={proc32ex_t[field]} "
                            yield record
                        case RecordMagic.AU_SUBJECT64EX_T.value:
                            subject64ex_t = c_aurecord.au_subject64ex_t(buf[bytes_read + 1 :])
                            bytes_read += 57
                            record["type"] = "subject64ex"
                            for field in subject64ex_t.fields:
                                record["message"] += f"{field}={subject64ex_t[field]} "
                            yield record
                        case RecordMagic.AU_PROCESS64EX_T.value:
                            process64ex_t = c_aurecord.au_proc64ex_t(buf[bytes_read + 1 :])
                            bytes_read += 57
                            record["type"] = "process64"
                            for field in process64ex_t.fields:
                                record["message"] += f"{field}={process64ex_t[field]} "
                            yield record
                        case RecordMagic.AU_INADDR_EX_T.value:
                            inaddr_ex_t = c_aurecord.au_inaddr_ex_t(buf[bytes_read + 1 :])
                            bytes_read += 21
                            record["type"] = "inaddr"
                            for field in inaddr_ex_t.fields:
                                record["message"] += f"{field}={inaddr_ex_t[field]} "
                            yield record
                        case RecordMagic.AU_SOCKETEX32_T.value:
                            socketex_t = c_aurecord.au_socket_ex_t(buf[bytes_read + 1 :])
                            length = socketex_t.atype * 2
                            bytes_read += (10 + length) + 1
                            record["type"] = "socketex"
                            for field in socketex_t.fields:
                                record["message"] += f"{field}={socketex_t[field]} "
                            yield record
                        case RecordMagic.AU_SOCKETINET32_T.value:
                            socketinet32_t = c_aurecord.au_socketinet32_t(buf[bytes_read + 1 :])
                            bytes_read += 9
                            record["type"] = "socketinet32"
                            for field in socketinet32_t.fields:
                                record["message"] += f"{field}={socketinet32_t[field]} "
                            yield record
                        case RecordMagic.AU_SOCKETINET128_T.value:
                            socketinet128_t = c_aurecord.au_socketinet128_t(buf[bytes_read + 1 :])
                            bytes_read += 21
                            record["type"] = "socketinet128"
                            for field in socketinet128_t.fields:
                                record["message"] += f"{field}={socketinet128_t[field]} "
                            yield record
                        case RecordMagic.AU_UNIXSOCK_T.value:
                            unixsock_t = c_aurecord.au_unixsock_t(buf[bytes_read + 1 :])
                            # TODO: Find a way to dynamically calculate the size of this record
                            bytes_read += (2 + unixsock_t._sizes["path"]) + 1
                            record["type"] = "unixsock"
                            for field in unixsock_t.fields:
                                record["message"] += f"{field}={unixsock_t[field]} "
                            yield record
                        case RecordMagic.AU_IDENTITY_INFO.value:
                            identity_info = c_aurecord.au_identity_info(buf[bytes_read + 1 :])
                            length = (
                                identity_info.signer_id_length
                                + identity_info.team_id_length
                                + identity_info.cdhash_length
                            )
                            bytes_read += 12 + length + 1
                            record["type"] = "identity_info"
                            for field in identity_info.fields:
                                record["message"] += f"{field}={identity_info[field]} "
                            yield record
                        case RecordMagic.AU_INVALID_T.value:
                            invalid_t = c_aurecord.au_invalid_t(buf[bytes_read + 1 :])
                            bytes_read += 3 + invalid_t.len
                            record["type"] = "invalid"
                            for field in invalid_t.fields:
                                record["message"] += f"{field}={invalid_t[field]} "
                            yield record
                        case _:
                            print(hexdump(buf))
                            print(f"[i] First byte of buf: {buf[bytes_read]}")
                            print(f"[i] Type of buf:       {type(buf[bytes_read])}")
                            break
        except EOFError:
            self.target.log.info("EOF reached")

    def _fetch_check_header(self):
        header_magic = self.fh.read(1)
        match header_magic:
            case b"\x14":
                self.target.log.info("Valid magic; parsing record length")
                # Get the size for the record
                recsize: int = c_aurecord.uint32(self.fh)
                full_rec = self.fh.read(recsize - 5)
                # repack the starting 4 bytes as BE and add remaining bytes
                buf: bytes = header_magic + p32(recsize, "big") + full_rec
                return recsize, buf
            case b"":
                self.target.log.info("EOF reached")
                return 0, 0
            case _:
                self.target.log.error(f"Invalid record: {hexdump(self.fh.read(10))}")
                raise Exception

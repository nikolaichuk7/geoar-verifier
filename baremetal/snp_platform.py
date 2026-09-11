#!/usr/bin/env python3
"""Host-side SEV-SNP platform control through /dev/sev (no library). Ubuntu 24.04+ host kernel with SNP support.

  snp_platform.py status        -> SNP_PLATFORM_STATUS: api, state, rmp_init, build, mask_chip_id, mask_chip_key, vlek_en, current/reported TCB
  snp_platform.py id            -> SEV_GET_ID2: the 64-byte chip identifier the KDS expects as hwID (must equal the guests' CHIP_ID)
  snp_platform.py config <mask_chip_id 0|1> [mask_chip_key 0|1]   -> SNP_SET_CONFIG (reported TCB left at 0 = committed)
Command numbers follow the upstream uapi header (see CMD below)."""
import sys, os, re, fcntl, ctypes, struct, json
# Command ids from include/uapi/linux/psp-sev.h (upstream, verified 2026-09-11); the distribution's libc headers can be
# older than the running kernel (Ubuntu 24.04 ships 6.8 headers, which lack the SNP_* entries), so they are not parsed.
CMD = {"SEV_FACTORY_RESET": 0, "SEV_PLATFORM_STATUS": 1, "SEV_PEK_GEN": 2, "SEV_PEK_CSR": 3, "SEV_PDH_GEN": 4, "SEV_PDH_CERT_EXPORT": 5,
       "SEV_PEK_CERT_IMPORT": 6, "SEV_GET_ID": 7, "SEV_GET_ID2": 8, "SNP_PLATFORM_STATUS": 9, "SNP_COMMIT": 10, "SNP_SET_CONFIG": 11, "SNP_VLEK_LOAD": 12}
def cmd_id(name): return CMD[name]
SEV_ISSUE_CMD = 0xC0105300                                   # _IOWR('S', 0, struct sev_issue_cmd {u32 cmd; u64 data; u32 error} __packed)
class Issue(ctypes.Structure): _pack_ = 1; _fields_ = [("cmd", ctypes.c_uint32), ("data", ctypes.c_uint64), ("error", ctypes.c_uint32)]
def issue(name, buf):
    io = Issue(cmd_id(name), ctypes.addressof(buf), 0); fd = os.open("/dev/sev", os.O_RDWR)
    try: fcntl.ioctl(fd, SEV_ISSUE_CMD, io); err = None
    except OSError as e: err = f"errno {e.errno} {e.strerror}"
    os.close(fd); return err, io.error
def status():
    buf = (ctypes.c_ubyte * 64)(); err, fw = issue("SNP_PLATFORM_STATUS", buf); b = bytes(buf)
    flags = struct.unpack_from("<I", b, 8)[0]
    return {"ioctl_error": err, "fw_error": fw, "api": f"{b[0]}.{b[1]}", "state": b[2], "is_rmp_init": b[3] & 1, "build_id": struct.unpack_from("<I", b, 4)[0],
            "mask_chip_id": flags & 1, "mask_chip_key": (flags >> 1) & 1, "vlek_en": (flags >> 2) & 1, "feature_info": (flags >> 3) & 1,
            "guest_count": struct.unpack_from("<I", b, 12)[0], "current_tcb": hex(struct.unpack_from("<Q", b, 16)[0]), "reported_tcb": hex(struct.unpack_from("<Q", b, 24)[0])}
def get_id():
    idbuf = (ctypes.c_ubyte * 64)(); req = (ctypes.c_ubyte * 16)(); struct.pack_into("<QI", req, 0, ctypes.addressof(idbuf), 64)
    err, fw = issue("SEV_GET_ID2", req); return {"ioctl_error": err, "fw_error": fw, "length": struct.unpack_from("<I", bytes(req), 8)[0], "id": bytes(idbuf).hex()}
def set_config(mask_chip_id, mask_chip_key=0):
    cfg = (ctypes.c_ubyte * 64)(); struct.pack_into("<QI", cfg, 0, 0, (mask_chip_id & 1) | ((mask_chip_key & 1) << 1))
    err, fw = issue("SNP_SET_CONFIG", cfg); return {"ioctl_error": err, "fw_error": fw, "requested": {"mask_chip_id": mask_chip_id, "mask_chip_key": mask_chip_key}}
if __name__ == "__main__":
    a = sys.argv[1:]
    out = status() if a[:1] == ["status"] else get_id() if a[:1] == ["id"] else set_config(int(a[1]), int(a[2]) if len(a) > 2 else 0) if a[:1] == ["config"] else {"usage": __doc__}
    print(json.dumps(out, indent=1))

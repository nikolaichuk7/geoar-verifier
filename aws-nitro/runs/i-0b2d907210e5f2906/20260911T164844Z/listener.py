import socket, struct, json, sys
srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); srv.bind((socket.VMADDR_CID_ANY, 5000)); srv.listen(1); srv.settimeout(150)
N = bytes.fromhex(open("nonce.hex").read().strip()); got = []
try:
    c, _ = srv.accept(); c.settimeout(120); c.sendall(struct.pack(">I", len(N)) + N)
    def recvall(k):
        b = b""
        while len(b) < k: b += c.recv(k - len(b))
        return b
    while True:
        name = recvall(struct.unpack(">B", recvall(1))[0]).decode(); data = recvall(struct.unpack(">I", recvall(4))[0])
        if name == "done": break
        open(name, "wb").write(data); got.append([name, len(data)])
except Exception as e: got.append(f"error: {e!r}")
json.dump(got, open("listener-result.json", "w"))

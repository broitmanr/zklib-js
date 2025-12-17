/**
 * zklibTcp.py.js
 * Implementación TCP 1:1 basada en pyzk (fanamini) zk/base.py
 *
 * En pyzk, ZK usa un socket TCP/UDP interno; aquí asumimos TCP y recibimos un net.Socket ya conectado.
 *
 * RESTRICCIÓN: NO ejecutar comandos en paralelo sobre el mismo socket TCP.
 */

'use strict';

const net = require('net');

/**
 * Constantes mínimas copiadas de const.py (pyzk).
 * Si ya las tienes en tu proyecto, puedes reemplazar este objeto por tu import.
 */
const Const = {
    USHRT_MAX: 65535,

    MACHINE_PREPARE_DATA_1: 20560, // 0x5050
    MACHINE_PREPARE_DATA_2: 32130, // 0x7282

    CMD_DB_RRQ: 7,
    CMD_USERTEMP_RRQ: 9,
    CMD_GET_FREE_SIZES: 50,

    CMD_CONNECT: 1000,
    CMD_EXIT: 1001,
    CMD_AUTH: 1102,

    CMD_PREPARE_DATA: 1500,
    CMD_DATA: 1501,
    CMD_FREE_DATA: 1502,
    _CMD_PREPARE_BUFFER: 1503,
    _CMD_READ_BUFFER: 1504,

    CMD_ACK_OK: 2000,
    CMD_ACK_ERROR: 2001,
    CMD_ACK_DATA: 2002,
    CMD_ACK_UNAUTH: 2005,
    CMD_ACK_UNKNOWN: 0xffff,

    // FCT
    FCT_USER: 5,

    CMD_USER_WRQ: 8,
    USER_DEFAULT: 0,
    USER_ADMIN: 14,
    CMD_TESTVOICE: 1017,

};

/**
 * Errores equivalentes a exception.py
 */
class ZKError extends Error {}
class ZKErrorConnection extends ZKError {}
class ZKErrorResponse extends ZKError {}
class ZKNetworkError extends ZKError {}

/**
 * User equivalente a user.py
 */
class UserPy {
    static encoding = 'utf8';

    constructor(uid, name, privilege, password = '', group_id = '', user_id = '', card = 0) {
        this.uid = uid;
        this.name = String(name);
        this.privilege = privilege;
        this.password = String(password);
        this.group_id = String(group_id);
        this.user_id = user_id;
        this.card = Number(card);
    }

    toString() {
        return `<User>: [uid:${this.uid}, name:${this.name} user_id:${this.user_id}]`;
    }
    toJSON() {
        return {
            uid: this.uid,
            name: this.name,
            privilege: this.privilege,
            password: this.password,
            group_id: this.group_id,
            user_id: this.user_id,
            card: this.card,
        };
    }
}

/**
 * Utilidades de packing/unpacking little-endian (equivalentes a struct.pack/unpack)
 */
function pack_u16_le(n) {
    const b = Buffer.allocUnsafe(2);
    b.writeUInt16LE(n & 0xffff, 0);
    return b;
}
function pack_i32_le(n) {
    const b = Buffer.allocUnsafe(4);
    b.writeInt32LE(n | 0, 0);
    return b;
}
function pack_u32_le(n) {
    const b = Buffer.allocUnsafe(4);
    b.writeUInt32LE(n >>> 0, 0);
    return b;
}

function unpack_u16_le(buf, off = 0) {
    return buf.readUInt16LE(off);
}
function unpack_u32_le(buf, off = 0) {
    return buf.readUInt32LE(off);
}
function unpack_i32_le(buf, off = 0) {
    return buf.readInt32LE(off);
}

/**
 * make_commkey copiado 1:1 de base.py (función global)
 * :contentReference[oaicite:5]{index=5}
 */
function make_commkey(key, session_id, ticks = 50) {
    key = Number.parseInt(key, 10);
    session_id = Number.parseInt(session_id, 10);
    let k = 0;

    for (let i = 0; i < 32; i++) {
        if (key & (1 << i)) k = (k << 1) | 1;
        else k = k << 1;
    }
    k += session_id;

    // pack(b'I', k) then unpack('BBBB')
    const bk = Buffer.allocUnsafe(4);
    bk.writeUInt32LE(k >>> 0, 0);

    const b0 = bk[0] ^ 'Z'.charCodeAt(0);
    const b1 = bk[1] ^ 'K'.charCodeAt(0);
    const b2 = bk[2] ^ 'S'.charCodeAt(0);
    const b3 = bk[3] ^ 'O'.charCodeAt(0);

    // pack('BBBB', ...) then unpack('HH') then pack('HH', swapped)
    const tmp = Buffer.from([b0, b1, b2, b3]);
    const h0 = tmp.readUInt16LE(0);
    const h1 = tmp.readUInt16LE(2);

    const swapped = Buffer.allocUnsafe(4);
    swapped.writeUInt16LE(h1, 0);
    swapped.writeUInt16LE(h0, 2);

    const B = ticks & 0xff;
    const out = Buffer.from([swapped[0] ^ B, swapped[1] ^ B, B, swapped[3] ^ B]);
    return out;
}

/**
 * Reader para TCP stream: acumulamos bytes y podemos leer N exactos sin perder nada.
 */
class TcpStreamReader {
    /**
     * @param {net.Socket} socket
     */
    constructor(socket) {
        this.socket = socket;
        this.buffer = Buffer.alloc(0);
        this.waiters = [];

        this._onData = (chunk) => {
            this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk]) : chunk;
            this._drain();
        };
        this._onError = (err) => {
            this._rejectAll(err);
        };
        this._onClose = () => {
            this._rejectAll(new Error('SOCKET_CLOSED'));
        };this._onTimeout = () => {
            this._rejectAll(new Error('SOCKET_TIMEOUT'));
        };

        socket.on('timeout', this._onTimeout);
        socket.on('data', this._onData);
        socket.on('error', this._onError);
        socket.on('close', this._onClose);
    }

    dispose() {
        this.socket.off('data', this._onData);
        this.socket.off('error', this._onError);
        this.socket.off('close', this._onClose);
        this.socket.off('timeout', this._onTimeout);
        this.waiters = [];
        this.buffer = Buffer.alloc(0);
    }

    _rejectAll(err) {
        const w = this.waiters;
        this.waiters = [];
        for (const item of w) item.reject(err);
    }

    _drain() {
        while (this.waiters.length) {
            const w = this.waiters[0];
            if (this.buffer.length < w.n) return;

            const out = this.buffer.subarray(0, w.n);
            this.buffer = this.buffer.subarray(w.n);
            this.waiters.shift();
            w.resolve(out);
        }
    }

    /**
     * Lee exactamente N bytes (espera hasta tenerlos).
     * @param {number} n
     * @returns {Promise<Buffer>}
     */
    readExact(n) {
        if (this.buffer.length >= n) {
            const out = this.buffer.subarray(0, n);
            this.buffer = this.buffer.subarray(n);
            return Promise.resolve(out);
        }
        return new Promise((resolve, reject) => {
            this.waiters.push({ n, resolve, reject });
        });
    }

    readExactTimeout(n, timeoutMs) {
        if (timeoutMs == null) return this.readExact(n);

        return Promise.race([
            this.readExact(n),
            new Promise((_, reject) =>
                setTimeout(() => reject(new Error('TIMEOUT_ON_READING_EXACT')), timeoutMs)
            )
        ]);
    }


    /**
     * Semántica Python recv(n): devuelve HASTA maxBytes (puede ser menos),
     * pero espera al menos minBytes para garantizar que haya algo que parsear.
     *
     * - Si ya hay >= minBytes en buffer: devuelve inmediatamente hasta maxBytes.
     * - Si no: espera hasta que haya minBytes, con timeout opcional.
     */
    recvUpTo(maxBytes, minBytes = 1, timeoutMs = null) {
        if (minBytes < 1) minBytes = 1;
        if (maxBytes < minBytes) maxBytes = minBytes;

        const take = () => {
            const n = Math.min(this.buffer.length, maxBytes);
            const out = this.buffer.subarray(0, n);
            this.buffer = this.buffer.subarray(n);
            return out;
        };

        // Si ya hay suficiente, devolvemos sin esperar
        if (this.buffer.length >= minBytes) {
            return Promise.resolve(take());
        }

        // Si no, esperamos a tener minBytes, pero luego devolvemos solo lo que haya (hasta maxBytes)
        return new Promise((resolve, reject) => {
            let timer = null;
            if (timeoutMs != null) {
                timer = setTimeout(() => {
                    // quitar este waiter de la cola
                    this.waiters = this.waiters.filter(w => w !== waiter);
                    reject(new Error('TIMEOUT_ON_READING'));
                }, timeoutMs);
            }

            const waiter = {
                n: minBytes,
                resolve: () => {
                    timer && clearTimeout(timer);
                    resolve(take());
                },
                reject: (err) => {
                    timer && clearTimeout(timer);
                    reject(err);
                }
            };

            this.waiters.push(waiter);
        });
    }

    /**
     * Devuelve lo que ya hay (sin esperar).
     */
    peekBuffer() {
        return this.buffer;
    }
}

/**
 * Implementación TCP equivalente al objeto ZK (solo subset para get_users / read_with_buffer / read_sizes)
 */
class ZKPyTcp {
    /**
     * @param {object} opts
     * @param {string} opts.ip
     * @param {number} [opts.port=4370]
     * @param {number} [opts.timeout=60_000]
     * @param {number} [opts.password=0]
     * @param {boolean} [opts.verbose=false]
     * @param {string} [opts.encoding='UTF-8'] (en JS se usa utf8)
     */
    constructor({ ip, port = 4370, timeout = 60_000, password = 0, verbose = false, encoding = 'UTF-8' }) {
        this.ip = ip;
        this.port = port;
        this.verbose = verbose;
        this.encoding = encoding;

        // TCP only
        this.tcp = true;
        this.force_udp = false;

        this.__timeout = timeout;
        this.__password = password;

        // Estado pyzk
        this.__session_id = 0;
        this.__reply_id = Const.USHRT_MAX - 1;

        this.__data_recv = null;
        this.__data = null;
        this.__header = null;

        this.__tcp_data_recv = null;
        this.__tcp_length = 0;

        this.__response = 0;

        // Flags
        this.is_connect = false;

        // Sizes
        this.users = 0;
        this.user_packet_size = 28; // default zk6 en pyzk, luego se ajusta

        this.__sock = null;
        this.__reader = null;

        // next ids
        this.next_uid = 1;
        this.next_user_id = '1';
    }

    async refresh_data() {
        return await this.read_sizes();
    }

    /**
     * Asocia un socket TCP ya conectado.
     * IMPORTANTE: este socket debe estar en modo "exclusive usage" para este handler.
     * @param {net.Socket} socket
     */
    attachSocket(socket) {
        this.__sock = socket;
        this.__sock.setTimeout(this.__timeout);
        this.__reader = new TcpStreamReader(socket);
    }


    /**
     * Detecta user_packet_size desde el reloj (pyzk-style):
     * - requiere this.users (read_sizes)
     * - lee el bloque de usuarios y calcula total_size/users
     */
    async __detect_user_packet_size() {
        // Asegurar que sabemos cuántos users hay
        await this.read_sizes();

        if (!this.users || this.users <= 0) {
            this.user_packet_size = 28;
            return this.user_packet_size;
        }

        const { data: userdata0, size } = await this.read_with_buffer(Const.CMD_USERTEMP_RRQ, Const.FCT_USER, 0);
        if (!userdata0 || size <= 4) {
            // fallback conservador
            this.user_packet_size = 28;
            return this.user_packet_size;
        }

        const total_size = unpack_u32_le(userdata0.subarray(0, 4), 0);
        const ups = total_size / this.users;

        // Validación suave: debe ser entero y un tamaño típico
        if (Number.isFinite(ups) && Number.isInteger(ups) && ups > 0) {
            this.user_packet_size = ups;
        } else {
            this.user_packet_size = 28;
        }

        return this.user_packet_size;
    }

    /**
     * Crea el top header TCP (pyzk __create_tcp_top)
     * :contentReference[oaicite:6]{index=6}
     */
    __create_tcp_top(packet) {
        const length = packet.length;
        const top = Buffer.concat([pack_u16_le(Const.MACHINE_PREPARE_DATA_1), pack_u16_le(Const.MACHINE_PREPARE_DATA_2), pack_u32_le(length)]);
        return Buffer.concat([top, packet]);
    }

    /**
     * test tcp top (pyzk __test_tcp_top)
     * :contentReference[oaicite:7]{index=7}
     */
    __test_tcp_top(packet) {
        if (packet.length <= 8) return 0;
        const h1 = unpack_u16_le(packet, 0);
        const h2 = unpack_u16_le(packet, 2);
        const len = unpack_u32_le(packet, 4);
        if (h1 === Const.MACHINE_PREPARE_DATA_1 && h2 === Const.MACHINE_PREPARE_DATA_2) return len;
        return 0;
    }

    /**
     * checksum (pyzk __create_checksum)
     * :contentReference[oaicite:8]{index=8}
     */
    __create_checksum(bytesArray /* number[] */) {
        let l = bytesArray.length;
        let checksum = 0;

        let i = 0;
        while (l > 1) {
            const v = (bytesArray[i] & 0xff) | ((bytesArray[i + 1] & 0xff) << 8);
            checksum += v;
            if (checksum > Const.USHRT_MAX) checksum -= Const.USHRT_MAX;
            i += 2;
            l -= 2;
        }
        if (l) checksum = checksum + (bytesArray[i] & 0xff);

        while (checksum > Const.USHRT_MAX) checksum -= Const.USHRT_MAX;

        checksum = ~checksum;

        while (checksum < 0) checksum += Const.USHRT_MAX;

        return pack_u16_le(checksum & 0xffff);
    }

    /**
     * create header (pyzk __create_header)
     * :contentReference[oaicite:9]{index=9}
     */
    __create_header(command, command_string, session_id, reply_id) {
        // buf = pack('<4H', command, 0, session_id, reply_id) + command_string
        const head = Buffer.concat([
            pack_u16_le(command),
            pack_u16_le(0),
            pack_u16_le(session_id),
            pack_u16_le(reply_id),
        ]);
        const buf = Buffer.concat([head, command_string]);

        // buf = unpack('8B' + '%sB' % len(command_string), buf) => array of bytes
        const bytesArray = Array.from(buf.values());
        const checksum = unpack_u16_le(this.__create_checksum(bytesArray), 0);

        // reply_id += 1; wrap at USHRT_MAX
        reply_id += 1;
        if (reply_id >= Const.USHRT_MAX) reply_id -= Const.USHRT_MAX;

        // pack('<4H', command, checksum, session_id, reply_id) + command_string
        const outHead = Buffer.concat([
            pack_u16_le(command),
            pack_u16_le(checksum),
            pack_u16_le(session_id),
            pack_u16_le(reply_id),
        ]);
        return Buffer.concat([outHead, command_string]);
    }

    async __send_command(command, command_string = Buffer.alloc(0), response_size = 8) {
        if (command !== Const.CMD_CONNECT && command !== Const.CMD_AUTH && !this.is_connect) {
            throw new ZKErrorConnection('instance are not connected.');
        }
        if (!this.__sock || !this.__reader) throw new ZKNetworkError('socket not attached');

        const buf = this.__create_header(command, command_string, this.__session_id, this.__reply_id);

        try {
            const topOut = this.__create_tcp_top(buf);

            await new Promise((resolve, reject) => {
                this.__sock.write(topOut, (err) => (err ? reject(err) : resolve()));
            });

            // 1) Traer "algo" de respuesta (hasta N), pero mínimo 8 bytes para poder decidir formato
            let chunk = await this.__reader.recvUpTo(
                response_size + 8,
                8,
                this.__timeout
            );

            // 2) Caso A: viene con TCP_TOP (pyzk)
            let tcpLen = this.__test_tcp_top(chunk);
            if (tcpLen !== 0) {
                const totalNeeded = tcpLen + 8; // top(8) + payload(tcpLen)

                if (chunk.length < totalNeeded) {
                    const more = await this.__reader.readExactTimeout(totalNeeded - chunk.length, this.__timeout);
                    chunk = Buffer.concat([chunk, more]);
                }

                // MUY IMPORTANTE: no recortar si chunk trae bytes extra (coalesced frames)
                this.__tcp_data_recv = chunk;
                this.__tcp_length = tcpLen;
            } else {
                // 3) Caso B: NO hay TCP_TOP. Interpretamos chunk como ZK_PAYLOAD directo.
                // Necesitamos al menos 8 bytes para header ZK.
                if (chunk.length < 8) {
                    const more = await this.__reader.readExactTimeout(8 - chunk.length,this.__timeout);
                    chunk = Buffer.concat([chunk, more]);
                }

                // En este modo, fabricamos un "top" dummy de 8 bytes para mantener offsets:
                // tcp_data_recv[8:16] debe apuntar al header ZK real
                const dummyTop = Buffer.alloc(8, 0);
                this.__tcp_data_recv = Buffer.concat([dummyTop, chunk]);

                // tcp_length (payload sin top) = largo del chunk real
                this.__tcp_length = chunk.length;
            }

            // 4) Parsear header ZK SIEMPRE desde [8:16], igual que pyzk
            const hdr = this.__tcp_data_recv.subarray(8, 16);
            this.__header = [
                unpack_u16_le(hdr, 0),
                unpack_u16_le(hdr, 2),
                unpack_u16_le(hdr, 4),
                unpack_u16_le(hdr, 6),
            ];

            this.__data_recv = this.__tcp_data_recv.subarray(8);

            this.__response = this.__header[0];
            this.__reply_id = this.__header[3];
            this.__data = this.__data_recv.subarray(8);

            if ([Const.CMD_ACK_OK, Const.CMD_PREPARE_DATA, Const.CMD_DATA].includes(this.__response)) {
                return { status: true, code: this.__response };
            }
            return { status: false, code: this.__response };
        } catch (e) {
            throw new ZKNetworkError(String(e && e.message ? e.message : e));
        }
    }




    /**
     * __get_data_size (pyzk)
     * :contentReference[oaicite:11]{index=11}
     */
    __get_data_size() {
        if (this.__response === Const.CMD_PREPARE_DATA) {
            return unpack_u32_le(this.__data.subarray(0, 4), 0);
        }
        return 0;
    }

    /**
     * __recieve_raw_data (pyzk)
     * :contentReference[oaicite:12]{index=12}
     */
    async __recieve_raw_data(size) {
        const chunks = [];
        let remaining = size;
        while (remaining > 0) {
            const part = await this.__reader.readExactTimeout(remaining, this.__timeout);
            chunks.push(part);
            remaining -= part.length;
        }
        return Buffer.concat(chunks);
    }

    /**
     * __recieve_tcp_data (pyzk)
     * Esta función es la más sensible; se respeta la misma estructura del código Python (incluyendo "broken header").
     * :contentReference[oaicite:13]{index=13}
     */
    async __recieve_tcp_data(data_recv, size) {
        const data = [];

        // El Python reintenta completar DATA si llega incompleto.
        const recieved = data_recv.length;

        // response = unpack('HHHH', data_recv[8:16])[0]
        const response = unpack_u16_le(data_recv.subarray(8, 10), 0);

        if (recieved >= (size + 32)) {
            if (response === Const.CMD_DATA) {
                const resp = data_recv.subarray(16, size + 16);
                return { resp, brokenHeader: data_recv.subarray(size + 16) };
            }
            return { resp: null, brokenHeader: Buffer.alloc(0) };
        }

        // try DATA incomplete
        data.push(data_recv.subarray(16, size + 16));
        let missing = size - (recieved - 16);

        let broken_header = Buffer.alloc(0);
        if (missing < 0) {
            // En python: broken_header = data_recv[size:]
            broken_header = data_recv.subarray(missing);
        }

        if (missing > 0) {
            const extra = await this.__recieve_raw_data(missing);
            data.push(extra);
        }

        return { resp: Buffer.concat(data), brokenHeader: broken_header };
    }

    /**
     * __recieve_chunk (pyzk)
     * :contentReference[oaicite:14]{index=14} :contentReference[oaicite:15]{index=15}
     */
    async __recieve_chunk() {
        if (this.__response === Const.CMD_DATA) {
            // TCP path
            if (this.__data.length < (this.__tcp_length - 8)) {
                const need = (this.__tcp_length - 8) - this.__data.length;
                const more_data = await this.__recieve_raw_data(need);
                return Buffer.concat([this.__data, more_data]);
            }
            return this.__data;
        }
        if (this.__response === Const.CMD_PREPARE_DATA) {
            const data = [];
            const size = this.__get_data_size();
            
            // TCP logic: si len(self.__data) >= (8+size) data_recv = self.__data[8:] else recv(size+32)
            // :contentReference[oaicite:16]{index=16}
            let data_recv;
            if (this.__data.length >= (8 + size)) {
                data_recv = this.__data.subarray(8);
            } else {
                // self.__data[8:] + self.__sock.recv(size + 32)
                const rest = this.__data.subarray(8);
                

                // Queremos completar hasta tener (8 + size) bytes dentro de self.__data (payload ZK).
                const target = 8 + size;
                const missing = target - this.__data.length;

                if (missing > 0) {
                    const more = await this.__reader.readExactTimeout(missing, this.__timeout);
                    data_recv = Buffer.concat([rest, more]);
                } else {
                    // por seguridad (no debería entrar acá si estamos en else)
                    data_recv = rest;
                }

            }

            const { resp, brokenHeader } = await this.__recieve_tcp_data(data_recv, size);
            if (resp == null) return null;

            data.push(resp);

            // get CMD_ACK_OK
            // si brokenHeader < 16 => recv(16), si no usa brokenHeader
            let ackBuf;
            if (brokenHeader.length < 16) {
                const need = 16 - brokenHeader.length;
                const more = await this.__reader.readExactTimeout(need, this.__timeout);
                ackBuf = Buffer.concat([brokenHeader, more]);
            } else {
                ackBuf = brokenHeader;
            }

            // validar tcp top
            if (!this.__test_tcp_top(ackBuf)) return null;

            const ackResp = unpack_u16_le(ackBuf.subarray(8, 10), 0);
            if (ackResp === Const.CMD_ACK_OK) {
                return Buffer.concat(data);
            }
            return null;
        }

        return null;
    }

    /**
     * __read_chunk (pyzk)
     * :contentReference[oaicite:17]{index=17}
     */
    async __read_chunk(start, size) {
        for (let retries = 0; retries < 3; retries++) {
            const command = Const._CMD_READ_BUFFER;
            const command_string = Buffer.concat([pack_i32_le(start), pack_i32_le(size)]);

            const response_size = size + 32; // TCP
            
            const cmd_response = await this.__send_command(command, command_string, response_size);
            
            const data = await this.__recieve_chunk();
            
            if (data != null) return data;
        }
        throw new ZKErrorResponse(`can't read chunk ${start}:[${size}]`);
    }

    /**
     * free_data (pyzk)
     * :contentReference[oaicite:18]{index=18}
     */
    async free_data() {
        const cmd_response = await this.__send_command(Const.CMD_FREE_DATA);
        if (cmd_response.status) return true;
        throw new ZKErrorResponse("can't free data");
    }

    /**
     * read_with_buffer (pyzk)
     * Devuelve {data, size} equivalente a (bytes, size) en Python.
     * :contentReference[oaicite:19]{index=19}
     */
    async read_with_buffer(command, fct = 0, ext = 0) {
        const MAX_CHUNK = 0xFFc0; // TCP
        // pack('<bhii', 1, command, fct, ext)
        // b: int8, h: int16, i: int32, i: int32
        const command_string = Buffer.concat([
            Buffer.from([1]),              // b
            pack_u16_le(command),          // h (en python es signed short, pero valores entran)
            pack_i32_le(fct),              // i
            pack_i32_le(ext),              // i
        ]);

        const response_size = 1024;
        const data = [];
        let start = 0;

        const cmd_response = await this.__send_command(Const._CMD_PREPARE_BUFFER, command_string, response_size);
    
        if (!cmd_response.status) throw new ZKErrorResponse('RWB Not supported');

        // Si code == CMD_DATA, retorna self.__data (+ raw si falta)
        // :contentReference[oaicite:20]{index=20}
        if (cmd_response.code === Const.CMD_DATA) {
            if (this.__data.length < (this.__tcp_length - 8)) {
                const need = (this.__tcp_length - 8) - this.__data.length;
                const more_data = await this.__recieve_raw_data(need);
                const joined = Buffer.concat([this.__data, more_data]);
                return { data: joined, size: this.__data.length + more_data.length };
            }
            return { data: this.__data, size: this.__data.length };
        }
        

        // size = unpack('I', self.__data[1:5])[0]
        const size = unpack_u32_le(this.__data.subarray(1, 5), 0);

        const remain = size % MAX_CHUNK;
        const packets = Math.floor((size - remain) / MAX_CHUNK);

        for (let i = 0; i < packets; i++) {
            data.push(await this.__read_chunk(start, MAX_CHUNK));
            start += MAX_CHUNK;
        }
        
        if (remain) {
            
            const chunk =await this.__read_chunk(start, remain)
            
            data.push(chunk);
            start += remain;
        }
      
        await this.free_data();
        return { data: Buffer.concat(data), size: start };
    }

    /**
     * read_sizes (pyzk) — subset para users
     * :contentReference[oaicite:21]{index=21}
     */
    async read_sizes() {
        
        const response_size = 1024;
        const cmd_response = await this.__send_command(Const.CMD_GET_FREE_SIZES, Buffer.alloc(0), response_size);
        if (!cmd_response.status) throw new ZKErrorResponse("can't read sizes");

        // En Python: si len(__data) >= 80 => unpack('20i', __data[:80]); users=fields[4]
        if (this.__data.length >= 80) {
            // 20 * int32
            const fields = [];
            for (let i = 0; i < 20; i++) {
                fields.push(unpack_i32_le(this.__data, i * 4));
            }
            this.users = fields[4];
            // pyzk sigue con otros campos (fingers, records, etc). Aquí no es necesario para get_users.
            this.__data = this.__data.subarray(80);
        }
        return true;
    }

    /**
     * get_users (pyzk) — 1:1
     * :contentReference[oaicite:22]{index=22}
     */
    async get_users() {
        await this.read_sizes();

        if (this.users === 0) {
            this.next_uid = 1;
            this.next_user_id = '1';
            return [];
        }

        const users = [];
        let max_uid = 0;

        const { data: userdata0, size } = await this.read_with_buffer(Const.CMD_USERTEMP_RRQ, Const.FCT_USER, 0);
        if (size <= 4) {
            // pyzk imprime warning y retorna []
            return [];
        }

        // total_size = unpack("I", userdata[:4])[0]
        const total_size = unpack_u32_le(userdata0.subarray(0, 4), 0);

        // user_packet_size = total_size / self.users
        this.user_packet_size = total_size / this.users;

        let userdata = userdata0.subarray(4);

        if (this.user_packet_size === 28) {
            while (userdata.length >= 28) {
                const chunk = userdata.subarray(0, 28);

                // unpack('<HB5s8sIxBhI', chunk.ljust(28)[:28])
                // uid:u16, privilege:u8, password:5s, name:8s, card:u32, group_id:u8, timezone:i16, user_id:u32
                const uid = chunk.readUInt16LE(0);
                const privilege = chunk.readUInt8(2);

                const passwordRaw = chunk.subarray(3, 3 + 5);
                const nameRaw = chunk.subarray(8, 8 + 8);

                const card = chunk.readUInt32LE(16);
                const group_id = chunk.readUInt8(20);
                // timezone = int16 at 22 (but in pyzk it's 'h' after 'B' and padding 'x' placed before it)
                const timezone = chunk.readInt16LE(22);
                const user_id_num = chunk.readUInt32LE(24);

                if (uid > max_uid) max_uid = uid;

                const password = passwordRaw.toString('utf8').split('\u0000')[0];
                let name = nameRaw.toString('utf8').split('\u0000')[0].trim();

                const group_id_s = String(group_id);
                const user_id = String(user_id_num);

                if (!name) name = `NN-${user_id}`;

                users.push(new UserPy(uid, name, privilege, password, group_id_s, user_id, card).toJSON());

                userdata = userdata.subarray(28);
                void timezone; // se mantiene por paridad con unpack, aunque no lo usemos
            }
        } else {
            // 72 bytes
            while (userdata.length >= 72) {
                const chunk = userdata.subarray(0, 72);

                // unpack('<HB8s24sIx7sx24s', ...)
                const uid = chunk.readUInt16LE(0);
                const privilege = chunk.readUInt8(2);
                const passwordRaw = chunk.subarray(3, 3 + 8);
                const nameRaw = chunk.subarray(11, 11 + 24);

                // 'I' está luego de 24s => offset 35, ocupa 4 bytes
                const card = chunk.readUInt32LE(35);

                // 'x7s' => 1 byte pad + 7 bytes group_id: offsets 39..46
                const groupRaw = chunk.subarray(40, 40 + 7);

                // 'x24s' => 1 pad + 24 user_id: offsets 47..70
                const userIdRaw = chunk.subarray(48, 48 + 24);

                let password = passwordRaw.toString('utf8').split('\u0000')[0];
                let name = nameRaw.toString('utf8').split('\u0000')[0].trim();
                let group_id = groupRaw.toString('utf8').split('\u0000')[0].trim();
                let user_id = userIdRaw.toString('utf8').split('\u0000')[0];

                if (uid > max_uid) max_uid = uid;
                if (!name) name = `NN-${user_id}`;

                users.push(new UserPy(uid, name, privilege, password, group_id, user_id, card).toJSON());

                userdata = userdata.subarray(72);
            }
        }

        max_uid += 1;
        this.next_uid = max_uid;
        this.next_user_id = String(max_uid);

        // while True: si existe user_id == next_user_id, incrementa
        while (users.some((u) => u.user_id === this.next_user_id)) {
            max_uid += 1;
            this.next_user_id = String(max_uid);
        }

        return users;
    }

    async executeCmdPy(command, command_string = Buffer.alloc(0), response_size = 8) {
        const res = await this.__send_command(command, command_string, response_size);
        return {
            ...res,
            response: this.__response,
            header: this.__header,
            session_id: this.__session_id,
            reply_id: this.__reply_id,
            data: this.__data,          // payload ZK (sin header)
            data_recv: this.__data_recv // header+payload ZK (sin TCP top)
        };
    }



    async set_user(uid = null, name = '', privilege = 0, password = '', group_id = '', user_id = '', card = 0) {
        const command = Const.CMD_USER_WRQ;

        // Asegurar user_packet_size real del reloj (no asumir 28)
        // Si ya fue detectado por get_users(), esto no recalcula.
        if (!this.user_packet_size || this.user_packet_size === 28) {
            // Ojo: 28 puede ser real; la detección confirma si corresponde
            await this.__detect_user_packet_size();
        }

        if (uid == null) {
            await this.get_users()
            uid = this.next_uid;
            if (!user_id) user_id = this.next_user_id;
        }
        if (!user_id) {
            user_id = String(uid); // ZK6 needs uid2 == uid
        }

        // privilege validation: only default/admin (pyzk)
        if (![Const.USER_DEFAULT, Const.USER_ADMIN].includes(privilege)) {
            privilege = Const.USER_DEFAULT;
        }
        privilege = parseInt(privilege, 10);

        const enc = 'utf8'; // en JS

        let command_string;
        try{
            if (this.user_packet_size === 28) {
                // pack('HB5s8sIxBHI', uid, privilege, password, name, card, group_id, 0, user_id)
                if (!group_id) group_id = 0;

                const passBuf = Buffer.from(String(password), enc);
                const nameBuf = Buffer.from(String(name), enc);

                const pass5 = Buffer.alloc(5, 0);
                passBuf.copy(pass5, 0, 0, Math.min(5, passBuf.length));

                const name8 = Buffer.alloc(8, 0);
                nameBuf.copy(name8, 0, 0, Math.min(8, nameBuf.length));

                const b = Buffer.alloc(28, 0);
                let o = 0;

                b.writeUInt16LE(parseInt(uid, 10) & 0xffff, o); o += 2;          // H
                b.writeUInt8(privilege & 0xff, o); o += 1;                       // B
                pass5.copy(b, o); o += 5;                                        // 5s
                name8.copy(b, o); o += 8;                                        // 8s
                b.writeUInt32LE((parseInt(card, 10) >>> 0), o); o += 4;           // I
                o += 1;                                                          // x
                b.writeUInt8(parseInt(group_id, 10) & 0xff, o); o += 1;           // B
                b.writeUInt16LE(0, o); o += 2;                                    // H (0)
                b.writeUInt32LE((parseInt(user_id, 10) >>> 0), o); o += 4;        // I

                command_string = b;
            } else {
                // pack('HB8s24s4sx7sx24s', uid, privilege, password, name_pad, card_str, group_id, user_id)
                // total 72 bytes (según el struct de pyzk)
                const passBuf = Buffer.from(String(password), enc);
                const pass8 = Buffer.alloc(8, 0);
                passBuf.copy(pass8, 0, 0, Math.min(8, passBuf.length));

                const nameBuf = Buffer.from(String(name), enc);
                const name24 = Buffer.alloc(24, 0);
                nameBuf.copy(name24, 0, 0, Math.min(24, nameBuf.length));

                const groupBuf = Buffer.from(String(group_id || ''), enc);
                const group7 = Buffer.alloc(7, 0);
                groupBuf.copy(group7, 0, 0, Math.min(7, groupBuf.length));

                const userIdBuf = Buffer.from(String(user_id), enc);
                const userId24 = Buffer.alloc(24, 0);
                userIdBuf.copy(userId24, 0, 0, Math.min(24, userIdBuf.length));

                const b = Buffer.alloc(72, 0);
                let o = 0;

                b.writeUInt16LE(parseInt(uid, 10) & 0xffff, o); o += 2;          // H
                b.writeUInt8(privilege & 0xff, o); o += 1;                       // B
                pass8.copy(b, o); o += 8;                                        // 8s
                name24.copy(b, o); o += 24;                                      // 24s
                // 4s: pyzk arma card_str = pack('<I', int(card))[:4]
                b.writeUInt32LE((parseInt(card, 10) >>> 0), o); o += 4;           // 4s
                o += 1;                                                          // x
                group7.copy(b, o); o += 7;                                       // 7s
                o += 1;                                                          // x
                userId24.copy(b, o); o += 24;                                    // 24s

                command_string = b;
            }

            const response_size = 1024;
            const cmd_response = await this.__send_command(command, command_string, response_size);

            if (!cmd_response.status) {
                throw new ZKErrorResponse("Can't set user");
            }

            await this.refresh_data();

            if (this.next_uid === uid) this.next_uid += 1;
            if (this.next_user_id === user_id) this.next_user_id = String(this.next_uid);

            return {
                'success':true,
                "data":{'uid':uid}
            }

        }catch (e){
            return {'success':false,'error':e.toString()}
        }

    }

    async test_voice(index = 0) {
        const command = Const.CMD_TESTVOICE;

        // pack("I", index) => uint32 little-endian (4 bytes)
        const command_string = Buffer.alloc(4);
        command_string.writeUInt32LE((parseInt(index, 10) >>> 0), 0);

        const cmd_response = await this.__send_command(command, command_string, 8);
        return !!cmd_response.status;
    }




    /**
     * connect (subset 1:1) usando socket ya conectado.
     * En pyzk, connect() crea socket, setea session/reply, manda CMD_CONNECT y si pide auth manda CMD_AUTH.
     * :contentReference[oaicite:23]{index=23}
     */
    async connect() {
        // en tu integración, attachSocket() debe hacerse antes (socket ya conectado por tu wrapper).
        this.__session_id = 0;
        this.__reply_id = Const.USHRT_MAX - 1;

        const cmd_response = await this.__send_command(Const.CMD_CONNECT, Buffer.alloc(0), 8);
        // pyzk: self.__session_id = self.__header[2]
        this.__session_id = this.__header[2];

        if (cmd_response.code === Const.CMD_ACK_UNAUTH) {
            const command_string = make_commkey(this.__password, this.__session_id);
            const auth_resp = await this.__send_command(Const.CMD_AUTH, command_string, 8);
            if (!auth_resp.status) throw new ZKErrorResponse('Unauthenticated');
        } else if (!cmd_response.status) {
            throw new ZKErrorResponse("Invalid response: Can't connect");
        }

        this.is_connect = true;
        return this;
    }

    /**
     * disconnect (subset 1:1)
     * :contentReference[oaicite:24]{index=24}
     */
    async disconnect() {
        const cmd_response = await this.__send_command(Const.CMD_EXIT, Buffer.alloc(0), 8);
        if (cmd_response.status) {
            this.is_connect = false;
            return true;
        }
        throw new ZKErrorResponse("can't disconnect");
    }



}

module.exports = {
    Const,
    ZKPyTcp,
    UserPy,
    make_commkey,
    ZKError,
    ZKErrorConnection,
    ZKErrorResponse,
    ZKNetworkError,
};

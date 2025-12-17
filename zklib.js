const ZKLibTCP = require('./zklibtcp')
// Py-only TCP protocol stack (1:1 port from fananimi/pyzk)
const { ZKPyTcp } = require('./zklibtcpPy')

const { ZKError } = require('./zkerror')

class ZKLib {
    /**
     * @param {string} ip
     * @param {number} port
     * @param {number} timeout
     * @param {number} inport - unused in PY-only mode (kept for signature compatibility)
     * @param {object} [options]
     * @param {number} [options.password=0]
     * @param {boolean} [options.verbose=false]
     */
    constructor(ip, port, timeout, inport, options = {}) {
        this.connectionType = null

        // We reuse the legacy TCP class ONLY to create/hold the net.Socket.
        // We do NOT use legacy protocol methods (executeCmd/getUsers/etc.) in PY-only mode.
        this.zklibTcp = new ZKLibTCP(ip, port, timeout)

        this.zklibTcpPy = null

        this.interval = null
        this.timer = null
        this.isBusy = false

        this.ip = ip
        this.port = port
        this.timeout = timeout

        this.password = options.password ?? 0
        this.verbose = options.verbose ?? false

        // kept for backwards compatibility; unused in PY-only mode
        this.inport = inport
    }

    /**
     * Wrapper retained for consistent error formatting.
     * In PY-only mode we only execute the TCP callback.
     */
    async functionWrapper(tcpCallback, _udpCallback, command = '') {
        if (!this.zklibTcp?.socket) {
            return Promise.reject(new ZKError(
                new Error(`Socket isn't connected !`),
                `[PY][TCP] ${command}`,
                this.ip
            ))
        }

        try {
            return await tcpCallback()
        } catch (err) {
            return Promise.reject(new ZKError(
                err,
                `[PY][TCP] ${command}`,
                this.ip
            ))
        }
    }

    /**
     * PY-only: create TCP socket and connect using the pyzk-compatible protocol stack.
     * NOTE: No UDP fallback in this mode.
     */
    async createSocket(cbErr, cbClose) {
        try {
            if (!this.zklibTcp.socket) {
                await this.zklibTcp.createSocket(cbErr, cbClose)
            }
            console.log("socket creado")
            // (Re)create the PY stack if missing or if socket changed
            if (!this.zklibTcpPy || this.zklibTcpPy.__sock !== this.zklibTcp.socket) {
                this.zklibTcpPy = new ZKPyTcp({
                    ip: this.ip,
                    port: this.port,
                    timeout: this.timeout,
                    password: this.password,
                    verbose: this.verbose,
                    encoding: 'UTF-8',
                })
                this.zklibTcpPy.attachSocket(this.zklibTcp.socket)
            }

            await this.zklibTcpPy.connect()
            await this.zklibTcpPy.read_sizes()
            this.connectionType = 'tcp'
            return true
        } catch (err) {
            this.connectionType = null
            // best-effort cleanup
            try { await this.zklibTcpPy?.disconnect() } catch (_) { }
            try { await this.zklibTcp?.disconnect() } catch (_) { }
            this.zklibTcpPy = null

            return Promise.reject(new ZKError(err, 'PY TCP CONNECT', this.ip))
        }
    }

    async disconnect() {
        try {
            if (this.zklibTcpPy) {
                await this.zklibTcpPy.disconnect()
            }
        } finally {
            try { await this.zklibTcp?.disconnect() } catch (_) { }
            this.zklibTcpPy = null
            this.connectionType = null
        }
        return true
    }

    // =========================
    // PY-implemented methods
    // =========================

    async getUsers() {
        return await this.functionWrapper(
            () => this.zklibTcpPy.get_users(),
            null,
            'GET_USERS'
        )
    }

    /**
     * PY-only: set user (delegates to pyzk-compatible set_user)
     * Firma compatible con la lib legacy (uid, userId, name, password, role, cardno)
     */
    async setUser(uid, userId, name, password = '', role = 0, cardno = 0, group_id = '') {
        return await this.functionWrapper(
            () => this.zklibTcpPy.set_user(uid, name, role, password, group_id, userId, cardno),
            null,
            'SET_USER'
        )
    }

    async testVoice(index = 0) {
        return await this.functionWrapper(
            () => this.zklibTcpPy.test_voice(index),
            null,
            'TEST_VOICE'
        );
    }

    // =========================
    // Not yet migrated methods
    // =========================

    _notImplemented(method) {
        return Promise.reject(new ZKError(
            new Error(`Not implemented in PY-only mode: ${method}`),
            `[PY_MODE] ${method}`,
            this.ip
        ))
    }

    async getTime() { return this._notImplemented('getTime') }
    async getSerialNumber() { return this._notImplemented('getSerialNumber') }
    async getDeviceName() { return this._notImplemented('getDeviceName') }
    async getPlatform() { return this._notImplemented('getPlatform') }
    async getOs() { return this._notImplemented('getOs') }
    async getWorkCode() { return this._notImplemented('getWorkCode') }
    async getFaceOn() { return this._notImplemented('getFaceOn') }
    async getSSR() { return this._notImplemented('getSSR') }
    async getFingerprintOn() { return this._notImplemented('getFingerprintOn') }
    async getUserTemplate() { return this._notImplemented('getUserTemplate') }
    async setUserTemplate() { return this._notImplemented('setUserTemplate') }
    async getAttendances() { return this._notImplemented('getAttendances') }
    async clearAttendanceLog() { return this._notImplemented('clearAttendanceLog') }
    async getInfo() { return this._notImplemented('getInfo') }
    async getRealTimeLogs() { return this._notImplemented('getRealTimeLogs') }
    async setRealTimeLogs() { return this._notImplemented('setRealTimeLogs') }
    async disableDevice() { return this._notImplemented('disableDevice') }
    async enableDevice() { return this._notImplemented('enableDevice') }
    async disconnectWithReboot() { return this._notImplemented('disconnectWithReboot') }
    async restart() { return this._notImplemented('restart') }
    async setTime() { return this._notImplemented('setTime') }
    async deleteUser() { return this._notImplemented('deleteUser') }
    async clearUsers() { return this._notImplemented('clearUsers') }
    async getConnectedIP() { return this._notImplemented('getConnectedIP') }

    // Scheduling helpers preserved
    clearIntervalSchedule() { this.interval && clearInterval(this.interval) }
    clearTimerSchedule() { this.timer && clearTimeout(this.timer) }
    setIntervalSchedule(cb, timer) { this.interval = setInterval(cb, timer) }
    setTimerSchedule(cb, timer) { this.timer = setTimeout(cb, timer) }
}

module.exports = ZKLib

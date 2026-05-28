const ZKLib = require('./zklib')

const IP = process.env.ZK_IP || '0.0.0.0'
const PORT = Number(process.env.ZK_PORT || 4370)
const TIMEOUT = Number(process.env.ZK_TIMEOUT || 10000)
const INPORT = Number(process.env.ZK_INPORT || 4000)
const PASSWORD = Number(process.env.ZK_PASSWORD || 0)
const COPY_SOURCE_IP = process.env.ZK_COPY_SOURCE_IP || ''
const COPY_TARGET_IP = process.env.ZK_COPY_TARGET_IP || IP
const COPY_USER_ID = process.env.ZK_COPY_USER_ID || ''
const COPY_FINGER_IDS = (process.env.ZK_COPY_FINGER_IDS || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean)

const TARGET_UID = process.env.ZK_UID || ''
const TARGET_USER_ID = process.env.ZK_USER_ID || ''
const FINGER_ID = Number(process.env.ZK_FINGER_ID || 0)
const SAVE_TEMPLATE = process.env.ZK_SAVE_TEMPLATE === '1'
const MOVE_TEMPLATE = process.env.ZK_MOVE_TEMPLATE === '1'
const MOVE_SOURCE_USER_ID = process.env.ZK_MOVE_SOURCE_USER_ID || '1112223'
const MOVE_TARGET_USER_ID = process.env.ZK_MOVE_TARGET_USER_ID || '1'
const MOVE_SOURCE_FINGER_ID = process.env.ZK_MOVE_SOURCE_FINGER_ID || ''

function shortFinger(finger) {
    if (!finger) return finger
    return {
        size: finger.size,
        uid: finger.uid,
        fid: finger.fid,
        valid: finger.valid,
        templatePreview: `${finger.template.slice(0, 32)}...`,
    }
}

function pickUser(users) {
    if (!users.length) return null

    if (TARGET_UID) {
        return users.find((user) => String(user.uid) === String(TARGET_UID)) || null
    }

    if (TARGET_USER_ID) {
        return users.find((user) => String(user.user_id) === String(TARGET_USER_ID)) || null
    }

    return users[0]
}

function findUserByUserId(users, userId) {
    return users.find((user) => String(user.user_id) === String(userId)) || null
}

async function connectDevice(ip, password = PASSWORD) {
    const device = new ZKLib(ip, PORT, TIMEOUT, INPORT, {
        password,
        verbose: true,
    })
    await device.createSocket()
    return device
}

async function copyUserTemplatesBetweenDevices() {
    if (!COPY_SOURCE_IP) {
        throw new Error('Set ZK_COPY_SOURCE_IP to copy templates between two devices.')
    }
    if (!COPY_TARGET_IP || COPY_TARGET_IP === '0.0.0.0') {
        throw new Error('Set ZK_COPY_TARGET_IP or ZK_IP for the target device.')
    }
    if (!COPY_USER_ID) {
        throw new Error('Set ZK_COPY_USER_ID with the user_id to copy.')
    }

    let source = null
    let target = null

    try {
        console.log(`Connecting source ${COPY_SOURCE_IP}...`)
        source = await connectDevice(COPY_SOURCE_IP)
        console.log(`Connecting target ${COPY_TARGET_IP}...`)
        target = await connectDevice(COPY_TARGET_IP)

        const sourceUsers = await source.getUsers()
        const sourceUser = findUserByUserId(sourceUsers, COPY_USER_ID)
        if (!sourceUser) {
            throw new Error(`Source user_id=${COPY_USER_ID} was not found.`)
        }

        const sourceTemplates = await source.getTemplates()
        let templatesToCopy = sourceTemplates.filter((finger) => String(finger.uid) === String(sourceUser.uid))
        if (COPY_FINGER_IDS.length) {
            templatesToCopy = templatesToCopy.filter((finger) => COPY_FINGER_IDS.includes(String(finger.fid)))
        }
        if (!templatesToCopy.length) {
            throw new Error(`No templates found for source user_id=${COPY_USER_ID}.`)
        }

        let targetUsers = await target.getUsers()
        let targetUser = findUserByUserId(targetUsers, COPY_USER_ID)
        let targetCreated = false

        if (!targetUser) {
            console.log(`Target user_id=${COPY_USER_ID} does not exist. Creating it...`)
            const created = await target.setUser(
                null,
                sourceUser.user_id,
                sourceUser.name,
                sourceUser.password,
                sourceUser.privilege,
                sourceUser.card,
                sourceUser.group_id
            )
            if (created && created.success === false) {
                throw new Error(`Could not create target user: ${created.error || 'unknown error'}`)
            }
            targetCreated = true
            targetUsers = await target.getUsers()
            targetUser = findUserByUserId(targetUsers, COPY_USER_ID)
            if (!targetUser) {
                throw new Error(`Target user_id=${COPY_USER_ID} was created but could not be read back.`)
            }
        }

        const targetTemplates = templatesToCopy.map((finger) => ({
            ...finger,
            uid: targetUser.uid,
        }))

        console.log(`Saving ${targetTemplates.length} templates into target user_id=${COPY_USER_ID}...`)
        const saved = await target.saveUserTemplate(targetUser, targetTemplates)

        console.log({
            sourceUser,
            targetUser,
            targetCreated,
            templatesCopied: targetTemplates.length,
            saved,
        })
    } finally {
        if (target) {
            try { await target.disconnect() } catch (_) { }
        }
        if (source) {
            try { await source.disconnect() } catch (_) { }
        }
    }
}

async function moveTemplateAndDeleteSource(zkInstance) {
    const users = await zkInstance.getUsers()
    console.log(`Users: ${users.length}`)

    const sourceUser = findUserByUserId(users, MOVE_SOURCE_USER_ID)
    const targetUser = findUserByUserId(users, MOVE_TARGET_USER_ID)

    if (!sourceUser) {
        throw new Error(`Source user_id=${MOVE_SOURCE_USER_ID} was not found.`)
    }
    if (!targetUser) {
        throw new Error(`Target user_id=${MOVE_TARGET_USER_ID} was not found.`)
    }

    console.log('Source user:', sourceUser)
    console.log('Target user:', targetUser)

    const templates = await zkInstance.getTemplates()
    let sourceTemplates = templates.filter((finger) => String(finger.uid) === String(sourceUser.uid))

    if (MOVE_SOURCE_FINGER_ID !== '') {
        sourceTemplates = sourceTemplates.filter((finger) => String(finger.fid) === String(MOVE_SOURCE_FINGER_ID))
    }

    if (!sourceTemplates.length) {
        throw new Error(`No templates found for source user_id=${MOVE_SOURCE_USER_ID}.`)
    }

    console.log(`Templates to move: ${sourceTemplates.length}`)
    sourceTemplates.forEach((finger) => console.log('Moving template:', shortFinger(finger)))

    const targetTemplates = sourceTemplates.map((finger) => ({
        ...finger,
        uid: targetUser.uid,
    }))

    console.log('Saving templates into target user before deleting source...')
    const saved = await zkInstance.saveUserTemplate(targetUser, targetTemplates)
    console.log('Save result:', saved)

    console.log(`Deleting source user user_id=${MOVE_SOURCE_USER_ID}, uid=${sourceUser.uid}...`)
    const deleted = await zkInstance.deleteUser(sourceUser.uid, sourceUser.user_id)
    console.log('Delete result:', deleted)
}

async function test() {
    if (COPY_SOURCE_IP) {
        await copyUserTemplatesBetweenDevices()
        return
    }

    if (!IP || IP === '0.0.0.0') {
        throw new Error('Set ZK_IP or edit IP at the top of test.js before running.')
    }

    const zkInstance = new ZKLib(IP, PORT, TIMEOUT, INPORT, {
        password: PASSWORD,
        verbose: true,
    })

    try {
        console.log(`Connecting to ${IP}:${PORT}...`)
        await zkInstance.createSocket()

        const info = await zkInstance.getInfo()
        console.log('Info:', info)

        if (MOVE_TEMPLATE) {
            await moveTemplateAndDeleteSource(zkInstance)
            return
        }

        const users = await zkInstance.getUsers()
        console.log(`Users: ${users.length}`)

        const user = pickUser(users)
        if (!user) {
            console.log('No user found for fingerprint test.')
            return
        }
        console.log('Selected user:', user)

        let finger = await zkInstance.getUserTemplate(user.uid, FINGER_ID, user.user_id)
        console.log(`Finger ${FINGER_ID}:`, shortFinger(finger))

        const templates = await zkInstance.getTemplates()
        console.log(`Templates: ${templates.length}`)
        if (templates.length) {
            console.log('First template:', shortFinger(templates[0]))
        }

        if (!finger && templates.length) {
            const fallback = templates[0]
            console.log(
                `Selected user/finger has no template. Retrying with first template: uid=${fallback.uid}, fid=${fallback.fid}`
            )
            finger = await zkInstance.getUserTemplate(fallback.uid, fallback.fid)
            console.log(`Finger ${fallback.fid}:`, shortFinger(finger))
            console.log(
                `Repeat this case with: ZK_IP=${IP} ZK_UID=${fallback.uid} ZK_FINGER_ID=${fallback.fid} node test.js`
            )
        }

        if (SAVE_TEMPLATE) {
            if (!finger) {
                console.log('Skipping save: selected finger was not found.')
            } else {
                console.log('Saving selected user + finger back to the device...')
                const saved = await zkInstance.saveUserTemplate(user, [finger])
                console.log('Save result:', saved)
            }
        } else {
            console.log('Save test skipped. Set ZK_SAVE_TEMPLATE=1 to write the selected template back.')
        }
    } finally {
        await zkInstance.disconnect()
        console.log('Disconnected.')
    }
}

test().catch((err) => {
    console.error('Test failed:', err)
    process.exitCode = 1
})

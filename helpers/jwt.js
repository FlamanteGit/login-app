const jwt = require('jsonwebtoken')

const generarJWT = (uid, name) => {
    const payload = { uid, name }
    const secretOrPrivateKey = process.env.SECRET_JWT_SEED

    return new Promise((resolve, reject) => {
        jwt.sign(payload, secretOrPrivateKey, {
            expiresIn: '24h',
        }, (err, token) => {
            if (err) {
                reject(err)
            } else {
                resolve(token)
            }
        })
    })
}

module.exports = { generarJWT }
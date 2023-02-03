const { response } = require("express");
const { validationResult } = require("express-validator");
const Usuario = require("../models/Usuario");
const bcrypt = require('bcryptjs');
const { generarJWT } = require("../helpers/jwt");

const crearUsuario = async (req, res = response) => {
    const { email, name, password } = req.body;

    try {
        // Verificar email
        const usuario = await Usuario.findOne({ email: email })
        if (usuario) {
            return res.status(400).json({
                ok: false,
                msg: 'El usuario ya existe con ese email'
            })
        }
        // Crear usuario con el modelo
        const dbUser = new Usuario(req.body)

        // Hash contraseña
        const salt = bcrypt.genSaltSync()
        dbUser.password = bcrypt.hashSync(password, salt)

        // Generar json web token
        const token = await generarJWT(dbUser.id, dbUser.name)

        // Crear usuario en DB
        await dbUser.save()

        // Generar respuesta exitosa
        return res.status(201).json({
            ok: true,
            uid: dbUser.id,
            name: name,
            token: token,
            email: email
        })

    } catch (error) {
        return res.status(500).json({
            ok: false,
            msg: "Por favor, hable con el administrador",
        });
    }




};

const loginUsuario = async (req, res = response) => {
    const { email, password } = req.body;

    try {
        const usuario = await Usuario.findOne({ email: email })
        if (!usuario) {
            return res.status(400).json({
                ok: false,
                msg: 'El correo no existe.'
            })
        }

        // Confirmar si el password hace match
        const validPassword = bcrypt.compareSync(password, usuario.password)

        if(!validPassword) {
            return res.status(400).json({
                ok: false,
                msg: 'La contraseña no es valida.'
            })
        }

        // Generar JWT
        const token = await generarJWT(usuario.id, usuario.name)

        // Respuesta del servicio
        return res.json({
            ok: true,
            uid: usuario.id,
            name: usuario.name,
            token: token,
            email: email
        })


    } catch (error) {
        return res.status(500).json({
            ok: false,
            msg: "Hable con el administrador",
        });
    }


};

const revalidarToken = async (req, res = response) => {

    const {uid} = req
    const usuario = await Usuario.findById(uid)

    // Generar json web token
    const token = await generarJWT(uid, usuario.name)

    return res.json({
        ok: true,
        uid,
        name: usuario.name,
        token,
        email: usuario.email
    });
};

module.exports = {
    crearUsuario,
    loginUsuario,
    revalidarToken,
};

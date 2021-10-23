// Login

// In / Out File System
//const rwdJson = require("../models/rwd-json.js");
const db = require ('../database/models');

//Requisitos de registracion
const { validationResult } = require ('express-validator');
const {getToken, getTokenData} = require("../functions/jwt.js");
const {configSMTP, getTemplateNewPass} = require("../functions/mailer.js");
const uuid = require("uuid");

// JSON path
const usersJson = "../../data/users.json";

/* JSON Layout
usuario   : e-mail (X)
password  : Contraseña (X)
nombre    : Nombres (X)
apellido  : Apellidos (X)
dni       : DNI (N)
celular   : Celular (N)
direccion : Direccion (X)
localidad : Localidad (X)
avatar    : Foto de perfil (X)
isAdmin   : true/false
active    : true/false
uuid      : uuid (formato especifico)
*/

// Controller
// Importante:
// funcion Restore: Configurar los parametros del protocolo SMTP
//                Configurar los datos de la cuenta autorizada a enviar mails.
//                Configurar la ruta de confirmacion en la funcion 'getTemplate'.
//                Esto debe hacerse en la funcion /src/functions/mailer.js

const controller = {
  // Muestra formulario de Login
  create:
    function(req, res) {
      res.render("login");
    }
  ,
  // Verifica credenciales del usuario
  store:
    function(req, res) {
      let validacionDeErrores = validationResult(req);
      if (validacionDeErrores.errors.length > 0) {
        console.log (validacionDeErrores.mapped())
        return res.render ('login', { 
          errors: validacionDeErrores.mapped(),
          oldData: req.body
        })
      } else {
        db.Users.findOne({
          where: {email: req.body.usuario}
        }).then(usuario => {
        req.session.usuarioLogueado = usuario;
          if (req.body.recordame) {
            res.cookie('recordame', usuario.id, {maxAge: 1000 * 60 * 60 * 24}); // 1 semana
          }
        res.redirect ('/home');
        });
      }
    }
  ,
  // Envia e-mail a la direccion informada para cambio de contraseña
  restore:
    async function(req, res) {
      let validacionDeErrores = validationResult(req);
      if (validacionDeErrores.errors.length > 0) {
        res.render ('login', { 
          errors: validacionDeErrores.mapped(),
          oldData: req.body
        });
      } else {
        db.User.findOne({
          where: {email: req.body.usuario}
        }).then(usuario => {
          if (usuario) {
            // Codigo para generar un token version 4 RFC4122
            let uuidStr = uuid.v4();
            // Guardar el uuidStr y el estado del usuario para su posterior verificacion
            usuario.uuid = uuidStr;
            // Obtiene token
            const nombre = usuario.nombre;
            const apellido = usuario.apellido;
            const email = usuario.email;
            const token = getToken({email, uuidStr});
            // Envia mail para activar
            // Parametros del protocolo SMTP
            let transporter = configSMTP();
            // Procesa el envio
            let adminAccount = transporter.options.auth.user;
            let info = transporter.sendMail({
              from: "'Sportal Admin' <" + adminAccount + ">",   // sender address
              to: email,                                        // list of receivers (separados por comas)
              subject: "Activación de Cuenta Personal",         // Subject line
              //text: "Esta es una prueba",                     // plain text body
              html: getTemplateNewPass(nombre, apellido, token) // HTML text body
            });
            if (info) {
              // Guarda el uuidStr y el estado del usuario para su posterior verificacion
              let newUsers = usuarios.map(function(elem) {
                if (elem.usuario == email) {
                  elem.active = false;
                  elem.uuid = uuidStr;
                }
                return elem;
              });
              res.send("Se ha enviado un correo a " + email);
            } else {
              res.send("No se ha podido enviar un correo a " + email);
            }
          } else {
            res.send("El usuario '" + email + "' no existe.");
          }
        }).catch(error => {
          res.send(error)
        })
      }
    }
,
  // Logoff usuario
  logout:
    function (req, res) {
      delete req.session.usuarioLogueado;
      res.redirect("/home");
    }
}; 

module.exports = controller;
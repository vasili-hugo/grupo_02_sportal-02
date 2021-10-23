var express = require('express');
var router = express.Router();
var controller = require("../controllers/usersCtrl.js");

//Requisitos para las validaciones 
const validation = require ('../middlewares/validations.js');
const authUsuario = require('../middlewares/authUsuario.js');

/* GET users listing. */
router.post("/", validation.uploadFile.single('avatar'), validation.register, controller.store);                                     // Crea un nuevo usuario
router.get("/", authUsuario.authUsuario, controller.create);                                                     // Muestra formulario de Registro
router.post("/:id", validation.uploadFile.single('avatar'), validation.edit, controller.editStore);                          // Edita usuario
router.get("/:id", authUsuario.testUsuario, controller.edit);                                                    // Muestra formulario edicion usuario
router.get("/confirm/:token", controller.confirm);                                                               // Confirma registro de usuario
router.get("/newPass/:token", controller.newPass);                                                               // Confirma blanqueo de contraseña

module.exports = router;
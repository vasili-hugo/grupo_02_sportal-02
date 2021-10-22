//const Productos = require("../models/Productos.js");
const config = require("./config.js");

const db = require("../database/models/");
const sequelize = db.sequelize;
const { Op } = require("sequelize");




/* GET test page. */
const test = {
  allRecords:
    function(req, res){
      db.Product.findAll({
        include: ["ages", "brands", "colors", "families", "headings", "sex"]
        //,attributes: ['brand_id']
      })
      .then(function (products) {
        console.log(products[1].colors)
        res.render('test', {products}); 
        //return products;
      }).catch(function (errmsg) {
        console.log("eerrror:" + errmsg);
        //errmsg.send("Error en [db.Products.findAll]:" + errmsg);
      })
    },
  
    retrive:
      function(req, res) {
        res.render('test');
      }
  }; 
  
  module.exports = test;
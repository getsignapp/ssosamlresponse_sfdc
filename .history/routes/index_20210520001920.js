var express = require('express');
const fs = require('fs');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  var message = fs.readFile('public/base.xml', 'utf-8');
  
  var dtF = new Date(new Date().getTime() + (1 * 60000));
  var dtP = new Date(new Date().getTime() - (1 * 60000));

  
  res.render('index', { title: 'Express' });
});

module.exports = router;

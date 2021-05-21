var express = require('express');
var fs = require('fs');
var SignedXml = require('xml-crypto').SignedXml;
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  var privatekey = fs.readFileSync('public/privatekey.key', 'utf-8').toString();
  var cert = fs.readFileSync('public/cert.crt', 'utf-8').toString();
  
  var message = fs.readFileSync('public/base.xml', 'utf-8').toString();
  
  var dtF = new Date(new Date().getTime() + (1 * 60000));
  var dtP = new Date(new Date().getTime() - (1 * 60000));

  message = message.replace(/TIMEGRT/g , dtF.toISOString());
  message = message.replace(/TIMESML/g , dtP.toISOString());
  //console.log(message);

  var sig = new SignedXml();
  sig.signingKey = cert;
  sig.computeSignature(message);
  console.log(sig.getSignedXml());
  
  res.render('index', { title: 'Express' });
});

module.exports = router;

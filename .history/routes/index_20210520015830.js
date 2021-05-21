var express = require('express');
var fs = require('fs');
var SignedXml = require('xml-crypto').SignedXml;
var FileKeyInfo = require('xml-crypto').FileKeyInfo;
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
  sig.addReference("//*[local-name(.)='Assertion']");
  sig.signingKey = fs.readFileSync("public/privatekey.key");
  sig.computeSignature(message,{
    prefix: 'ds'
  });
  
  var saml = sig.getSignedXml();
  var doc = new dom().parseFromString(saml);
  var signature = select(doc, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0]
	var sig2 = new SignedXml()
	sig2.keyInfoProvider = new FileKeyInfo("public/cert.crt")
	sig2.loadSignature(signature)
	var res = sig2.checkSignature(xml);
  saml = sig2.getSignedXml();

  res.render('index', { title: 'Express', msg : saml, msgbase64 : new Buffer(saml).toString('base64') });
});

module.exports = router;

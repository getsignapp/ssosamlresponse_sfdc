var express = require('express');
var fs = require('fs');
var SignedXml = require('xml-crypto').SignedXml;
var select = require('xml-crypto').xpath;
var crypto = require('crypto');
var https = require('https');
var builder = require('xmlbuilder');
var DOMParser = require('xmldom').DOMParser;
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  var dtF = new Date(new Date().getTime() + (1 * 60000));
  var dtP = new Date(new Date().getTime() - (1 * 60000));
  
  var xml = builder.create('saml2p:Response',{ encoding: 'utf-8' })
  .att('xmlns:saml2p', 'urn:oasis:names:tc:SAML:2.0:protocol')
  .att('xmlns:xs', 'http://www.w3.org/2001/XMLSchema')
  .att('Destination', 'https://ankittrailhead-dev-ed.my.salesforce.com?so=00D7F000002CITw')
  .att('ID', '_12345-67890')
  .att('IssueInstant', dtP.toISOString())
  .att('Version', "2.0")
  .ele('saml2:Issuer' , 'http://localhost:3000/')
  .att('xmlns:saml2', "urn:oasis:names:tc:SAML:2.0:assertion").up()
  .ele('saml2p:Status')
  .ele('saml2p:StatusCode')
  .att('Value', "urn:oasis:names:tc:SAML:2.0:status:Success").up().up()
  .ele('saml2:Assertion')
    .att('xmlns:saml2', "urn:oasis:names:tc:SAML:2.0:assertion")
    .att('ID', '_12345-abcdef')
    .att('IssueInstant', dtP.toISOString())
    .att('Version', "2.0")
    .ele('saml2:Issuer' , 'http://localhost:3000/').up()
    .ele('saml2:Subject')
      .ele('saml2:NameID', '12345678')
      .att('Format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified').up()
      .ele('saml2:SubjectConfirmation')
      .att('Method', 'urn:oasis:names:tc:SAML:2.0:cm:bearer')
        .ele('saml2:SubjectConfirmationData')
        .att('NotOnOrAfter', dtF.toISOString())
        .att('Recipient', "https://ankittrailhead-dev-ed.my.salesforce.com?so=00D7F000002CITw").up()
      .up()
    .up()
      .ele('saml2:Conditions')
      .att('NotBefore', dtP.toISOString())
      .att('NotOnOrAfter', dtF.toISOString())
        .ele('saml2:AudienceRestriction')
          .ele('saml2:Audience' , 'https://ankittrailhead-dev-ed.my.salesforce.com/').up()
        .up()
      .up()
      .ele('saml2:AuthnStatement')
      .att('AuthnInstant', dtP.toISOString())
        .ele('saml2:AuthnContext')
          .ele('saml2:AuthnContextClassRef' , 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified').up()
        .up()
      .up()
      .ele('saml2:AttributeStatement')
        .ele('saml2:Attribute')
        .att('Name', 'ssoStartPage')
        .att('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified')
          .ele('saml2:AttributeValue' , 'http://axiomsso.herokuapp.com/RequestSamlResponse.action')
          .att('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
          .att('xsi:type', 'xs:string').up()
        .up()
        .ele('saml2:Attribute')
        .att('Name', 'logoutURL')
        .att('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified')
          .ele('saml2:AttributeValue')
          .att('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
          .att('xsi:type', 'xs:string').up()
        .up()
      .up()
  .up()
  .end({ pretty: false});

  var xmlDoc = new DOMParser().parseFromString(xml,"text/xml");
  var message = xmlDoc.getElementsByTagName("saml2:Assertion").toString();

  /*var message = fs.readFileSync('public/base.xml', 'utf-8').toString();
  message = message.replace(/TIMEGRT/g , dtF.toISOString());
  message = message.replace(/TIMESML/g , dtP.toISOString());*/
  message = message.replace(/>\s*/g, '>'); 
  message = message.replace(/\s*</g, '<');
  message = message.replace(new RegExp( "\\n", "g" ), "");

  function MyKeyInfo() {
	  this.getKeyInfo = function(key, prefix) {
        prefix = prefix || '';
        prefix = prefix ? prefix + ':' : prefix;
        
        var publicKey = fs.readFileSync("public/rsa/rsa256/cert.cer", "utf8").replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").trim();;

	      return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + publicKey + "</" + prefix + "X509Certificate></" + prefix + "X509Data>"
	  }
	  this.getKey = function(keyInfo) {
	    //you can use the keyInfo parameter to extract the key in any way you want      
	    return fs.readFileSync("public/rsa/rsa256/cert.cer");
	  }
	}

  /*function MySignatureAlgorithm() {
	  this.getSignature = function(signedInfo, signingKey) {            
	    const sign = crypto.createSign('SHA1');
      sign.update(signedInfo);
      sign.end();
      const signature = sign.sign(signingKey);
      return signature.toString('base64');
	  }

	  this.getAlgorithmName = function() {
	    return "http://www.w3.org/2000/09/xmldsig#dsa-sha1"
	  }

	}
  SignedXml.SignatureAlgorithms["http://www.w3.org/2000/09/xmldsig#dsa-sha1"] = MySignatureAlgorithm; */

  var sig = new SignedXml();
  //sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
  sig.addReference("//*[local-name(.)='Response']");
  sig.signingKey = fs.readFileSync("public/rsa/rsa256/privkey.pem");
  sig.keyInfoProvider = new MyKeyInfo();
  
  sig.computeSignature(message,{
    prefix: 'ds'
  });
  
  var saml = sig.getSignedXml();
  
  res.render('index', { title: 'Express', msg : saml, msgbase64 : new Buffer(saml).toString('base64') });
});

router.post('/', function(req, res, next) {
  var base64Str = req.body.base64;
  var raw = req.body.raw;
  var url = req.body.url;

  const data = 'SAMLResponse=' + base64Str + '&idpConfig.recipient=' + 'https://' + url + '/?so=00D7F000002CITw&RelayState=';
  
  const options = {
    hostname: url,
    port: 443,
    path: '/',
    method: 'POST',
    params : {
      'so' : '00D7F000002CITw'
    },
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': data.length,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
      'Origin': 'http://localhost:3000/',
      'Host': url
    }
  }
  
  const request = https.request(options, response => {
    console.log(`statusCode: ${response.statusCode}`);
    if(response.statusCode > 300 && response.statusCode < 400){
      console.log(response.headers.location);
      res.redirect(response.headers.location);
    }
    response.on('data', d => {
      process.stdout.write(d);
      res.redirect('https://' + url + '/');
    })
  })
  
  request.on('error', error => {
    console.error(error);
    //res.render('index', { title: 'Express', msg : raw, msgbase64 : base64Str });
    res.redirect('https://' + url + '/');
  })
  
  request.write(data);
  request.end();

});

module.exports = router;

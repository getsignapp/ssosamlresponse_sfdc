var express = require('express');
var fs = require('fs');
var SignedXml = require('xml-crypto').SignedXml;
var FileKeyInfo = require('xml-crypto').FileKeyInfo;
var dom = require('xmldom').DOMParser;
var select = require('xml-crypto').xpath;
var crypto = require('crypto');
var https = require('https');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  var privatekey = fs.readFileSync('public/dsaprivkey.pem');
  var cert = fs.readFileSync('public/dsapubkey.pem');
  
  var message = fs.readFileSync('public/base.xml', 'utf-8').toString();
  
  var dtF = new Date(new Date().getTime() + (1 * 60000));
  var dtP = new Date(new Date().getTime() - (1 * 60000));

  message = message.replace(/TIMEGRT/g , dtF.toISOString());
  message = message.replace(/TIMESML/g , dtP.toISOString());
  //console.log(message);

  function MyKeyInfo() {
	  this.getKeyInfo = function(key, prefix) {
        prefix = prefix || '';
        prefix = prefix ? prefix + ':' : prefix;
        
        var publicKey = 'MIIDOjCCAi0GByqGSM44BAEwggIgAoIBAQDfWf7NOoBxrzaju6fFyXRlNttEKUFAMI8plRVyN63Wgvz0a6KVjEJbqtd3g78p2BdXUE8GWxybh2awqq0F5OmCrParx50BdsILKCcux5o5IObgNZl9EpZ7hMXmxAuaOLnKBwcC1lwkveimSHL2cN/QyvlPYqNXgGjKfxdti7tr3TrrpQAzBSJ+J4xig0Kxq+aqKqA+U987Uh8pREXTv7N8haRUV9fwrADJLb349xvO7nx+WZInBpHn3quvlBrSKhykYW2cURZyYzPxC4pXwpL3aD1OxFRIugRevfeqIvtvWy4XmattEB3vmbmzOcquV5m0Ra0WB7LwVykldPfKuaXXAhUAxaX5J5Pbw7/vfnpmf9QRei0eKZUCggEAOCkVOSWD52fKzNNtJbqtw1zKZLffXRpfZXy2AUgwWzXFU55yQzbguyyCZBOXVrrN7LEmyAU6FvbWtCI/Qu8/WCSYBX82d4jZPUxjjm6+1zLWq3MhPXWA1xfmCTvFlgz4JjDTFbfq2K1i+S9F6a4U9T2tkroPvaXhu/zwr+Fkbc5p/Qk92vyQeDDeQoF25ZTnINPUmDKYVTgMfCgY7wOMgue/QqbBygWp+AxSsNMc1aDbVXn+8Ibi9o0Va/LBUAeaU/Z2uErxmhzgx2bwo3kpY+l27oAYVqsOQqrhpwP0zdwdIu+pX0fXGeWMbLWTEl3faET9LJWm5OkSI8UnIXtpSgOCAQUAAoIBAG/76fQ2p0n2FfUMMFqYFseTcjaA9SAWLuRiFp6Hvwa8OCWT0KjbkJok2DkO5f5AvVlc9MxxJuzUEyiPlaU6Dwgi9LI7dq/xOoJk9khmCHpaazso/OyUxgy4YZflaJeJyRp2j8GI439SAOM8QWowtZoxoZ43FJoTci8ZEXZKssE9+0LlVmYVgpIC+h0XTUaeG3iSZ96VFNCG9kQzlJax6odnShtF5GfeYib/KmW/S5joCMbaJOa82fQ4UpbxeFFx/1sub9m/07RVz52M0O2XtHvGw1/Sd2CSiTO8f6E+c21HJv6G70+JvbVIxZzBRjf6iCmN9AhVS8g7/pe9ltg+F9s=';
        
	      return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + publicKey + "</" + prefix + "X509Certificate></" + prefix + "X509Data>"
	  }
	  this.getKey = function(keyInfo) {
	    //you can use the keyInfo parameter to extract the key in any way you want      
	    return fs.readFileSync("public/dsapubkey.pem")
	  }
	}

  function MySignatureAlgorithm() {

	  /*sign the given SignedInfo using the key. return base64 signature value*/
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
  SignedXml.SignatureAlgorithms["http://www.w3.org/2000/09/xmldsig#dsa-sha1"] = MySignatureAlgorithm

  var sig = new SignedXml();
  sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
  sig.addReference("//*[local-name(.)='Response']");
  sig.signingKey = fs.readFileSync("public/dsaprivkey.pem");
  sig.keyInfoProvider = new MyKeyInfo();
  sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#dsa-sha1"
  
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

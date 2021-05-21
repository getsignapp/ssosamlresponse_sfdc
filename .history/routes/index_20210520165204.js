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
        
        var publicKey = 'MIIDeTCCAmGgAwIBAgIJAMG0wNZq8ZPeMA0GCSqGSIb3DQEBCwUAMDExCzAJBgNVBAYTAklOMRMwEQYDVQQIEwpTb21lLVN0YXRlMQ0wCwYDVQQKEwRTZWxmMB4XDTIxMDUyMDExMDQ1MloXDTIyMDUyMDExMDQ1MlowMTELMAkGA1UEBhMCSU4xEzARBgNVBAgTClNvbWUtU3RhdGUxDTALBgNVBAoTBFNlbGYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCzZlcqcwOdEdYSLWO2OVFqRQRBwOGp4ncZP7j9Aq0B88wqXU11nSsGx1dd40OwkaJj8s0ThYAfOzGrFCp92qveo8IURKf/eBm8nXZEIck2oAZ8PI3ZESge7gNyat2UNxAT60LMxCcSdBoMqvD1E8ZZMftCEVuOMaahdTIpZs8zRJlg+5ESZLiPi5ehZL9fVV7M/9s8g6XqDoEf7NSoufOXuD6vsPkH4ybKFEkJuTtASp94kNni6uwOzpgi7fv7DIV0ooYA8YQtpB1gnYBJKNMeWV/49oD0T/jwKrnfVW+k7KYNz27mUWFPupCi76T5rKEyHIo3zTcvtw5KR5gpkTHLAgMBAAGjgZMwgZAwHQYDVR0OBBYEFP7C3Rr3sSUhPvZ9gMTS5HbHwayVMGEGA1UdIwRaMFiAFP7C3Rr3sSUhPvZ9gMTS5HbHwayVoTWkMzAxMQswCQYDVQQGEwJJTjETMBEGA1UECBMKU29tZS1TdGF0ZTENMAsGA1UEChMEU2VsZoIJAMG0wNZq8ZPeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAF/XpOchYyZZwezcpuEQZ0muW3yv65osK/mon53Lt44tpl+z2lNizb2vyNFh3BK8mN/OK5U+AGW1v4+cLk5B9z6ZlIpgwPE/OkR4XsXCF2ALNwU26xOS2925j21IxlMVjoVWtith45vEiuVqYYiJz48GkO1Z+uwVDofxo8AFtFn8W2dAYPmQO72ZJIxPVhRy80lDwBioPFe17Hy4CtaltZFH1W2B2gnZSXCvpm3j7uyTLt4bRer9OuDlXjx0/bKBuc3LGJ9ImWKYcsjIX4DeQczfaPZIdB8yv7vqkrjdfEFTYwuDjSbfS5nixP0t65m6/HR3COtsSMiT6RURMXCoKaU=';
        
	      return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + publicKey + "</" + prefix + "X509Certificate></" + prefix + "X509Data>"
	  }
	  this.getKey = function(keyInfo) {
	    //you can use the keyInfo parameter to extract the key in any way you want      
	    return fs.readFileSync("public/rsa/rsa256/cert.cer")
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
  SignedXml.SignatureAlgorithms["http://www.w3.org/2000/09/xmldsig#dsa-sha1"] = MySignatureAlgorithm*/

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

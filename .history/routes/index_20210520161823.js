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
  var cert = fs.readFileSync('public/publickey.key');
  
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
        
        var publicKey = 'MIIDRjCCAjkGByqGSM44BAEwggIsAoIBAQCFHRi+OBitecOtblDz1vE+0qvnpCr9ufAdgywDDr1hbIFA0iVBnC3kEM2jGpYjXpIKD0knOaQDN/dC2gIKVZVlSB7g/Uz03afRWVm0V5sB141c4ccIr/6ry7JRSMnfqsWDK4KvxPf9jGElaS0Z2ffahjBvEOTTVmiMM/8q5YlpR1RjRMzwvkKTV5rLjcP4eVyURgkRGarakLXiajJoF3Ph2yKArCCz3omvQSsQQbh5YVebdG9K8tUVxp7zVvJgwmjmih1SkA31wCb4PAp2BmVDe2RO9GB54YNczJCtGN0a/ylL/r4Ld6pdcY8GpaeKKNQRQUawTX/EcIwSHu6e1TDXAiEAhX99AkGDWizTtSRVGjt1pVokCYUZFfkcdPNsVvIR1LkCggEAHrTJ7NXFuTEEHYW7XCIQ+Uuh4iwCMMzP0x8FLyMCpOG2PJ2A1SlDazjleknzowT5V3mjA3/1h8laJ7nbE9h9H+vDRSMs53IOspAijBUJxno7UubfJrf0iKwEtf/Pol7KBgkJK0sMggL9EGxAxUM/JoJAzINhWMwtmVywsbX4uE9D+UOFafiiWLaGSENkVpPiXTu4OwOLDtJHQgVoBTKdt6RfRhkNhnKK6wjcneXzXZ4N8ccbu4swlyf176gT+Ni+QUbyeu/pfrKvQh2pnOGi6yYc9xePq9iPrlMjEh75QB3lvR4s/1Y/Fq5kAO83aoMLB8bv9gCfmD6XPMVX+mQDLQOCAQUAAoIBABvIXH4arVp4V4hY6mAiP22Ht7brDIaSdDKDTTcxjs7PDjUuUfYpA7FJvbXWAqziWyv+9iOMxMnNeYqvLVXyW+9gkFETAGcDM5fF+tuJhvIa/G+UIBO5ewPYKdHXbobnxqEKtFQN+7FdOYnrXLGu8QeL/1IrI5uh20NBfo0by/4VQvtm2dFf7Se4JhDeWx2U975t4j3EYebkRw4nhg5BIdvVxcn4OHdDTgSg/7n+OuRcafwFas5Md1z+WHetPFEaNBB9+nGJ6GoqX/3srefGzXG3ebdUDZkKTOedRkSdFO6meY229g7yGOfXEb55Cdc3q4VibjeE0s+hun3ranlRNGg=';
        
	      return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + publicKey + "</" + prefix + "X509Certificate></" + prefix + "X509Data>"
	  }
	  this.getKey = function(keyInfo) {
	    //you can use the keyInfo parameter to extract the key in any way you want      
	    return fs.readFileSync("public/publickey.key")
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

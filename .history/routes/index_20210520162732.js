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
  var cert = fs.readFileSync('public/cert.cer');
  
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
        
        var publicKey = 'MIIEtjCCBHWgAwIBAgIJAL+YtuS6PsDcMAkGByqGSM44BAMwMTELMAkGA1UEBhMCSU4xEzARBgNVBAgTClNvbWUtU3RhdGUxDTALBgNVBAoTBFNlbGYwHhcNMjEwNTIwMTA0NjUyWhcNMjEwNjE5MTA0NjUyWjAxMQswCQYDVQQGEwJJTjETMBEGA1UECBMKU29tZS1TdGF0ZTENMAsGA1UEChMEU2VsZjCCAzowggItBgcqhkjOOAQBMIICIAKCAQEA31n+zTqAca82o7unxcl0ZTbbRClBQDCPKZUVcjet1oL89GuilYxCW6rXd4O/KdgXV1BPBlscm4dmsKqtBeTpgqz2q8edAXbCCygnLseaOSDm4DWZfRKWe4TF5sQLmji5ygcHAtZcJL3opkhy9nDf0Mr5T2KjV4Boyn8XbYu7a90666UAMwUifieMYoNCsavmqiqgPlPfO1IfKURF07+zfIWkVFfX8KwAyS29+Pcbzu58flmSJwaR596rr5Qa0iocpGFtnFEWcmMz8QuKV8KS92g9TsRUSLoEXr33qiL7b1suF5mrbRAd75m5sznKrleZtEWtFgey8FcpJXT3yrml1wIVAMWl+SeT28O/7356Zn/UEXotHimVAoIBADgpFTklg+dnyszTbSW6rcNcymS3310aX2V8tgFIMFs1xVOeckM24LssgmQTl1a6zeyxJsgFOhb21rQiP0LvP1gkmAV/NneI2T1MY45uvtcy1qtzIT11gNcX5gk7xZYM+CYw0xW36titYvkvRemuFPU9rZK6D72l4bv88K/hZG3Oaf0JPdr8kHgw3kKBduWU5yDT1JgymFU4DHwoGO8DjILnv0KmwcoFqfgMUrDTHNWg21V5/vCG4vaNFWvywVAHmlP2drhK8Zoc4Mdm8KN5KWPpdu6AGFarDkKq4acD9M3cHSLvqV9H1xnljGy1kxJd32hE/SyVpuTpEiPFJyF7aUoDggEFAAKCAQBv++n0NqdJ9hX1DDBamBbHk3I2gPUgFi7kYhaeh78GvDglk9Co25CaJNg5DuX+QL1ZXPTMcSbs1BMoj5WlOg8IIvSyO3av8TqCZPZIZgh6Wms7KPzslMYMuGGX5WiXickado/BiON/UgDjPEFqMLWaMaGeNxSaE3IvGRF2SrLBPftC5VZmFYKSAvodF01Gnht4kmfelRTQhvZEM5SWseqHZ0obReRn3mIm/yplv0uY6AjG2iTmvNn0OFKW8XhRcf9bLm/Zv9O0Vc+djNDtl7R7xsNf0ndgkokzvH+hPnNtRyb+hu9Pib21SMWcwUY3+ogpjfQIVUvIO/6XvZbYPhfbo4GTMIGQMB0GA1UdDgQWBBRSZtnG4yC/gaGyFrC1aofEQnlCVjBhBgNVHSMEWjBYgBRSZtnG4yC/gaGyFrC1aofEQnlCVqE1pDMwMTELMAkGA1UEBhMCSU4xEzARBgNVBAgTClNvbWUtU3RhdGUxDTALBgNVBAoTBFNlbGaCCQC/mLbkuj7A3DAMBgNVHRMEBTADAQH/MAkGByqGSM44BAMDMAAwLQIUEpXCqQHN/V52toXtlKkXOU6YvRICFQCqPbEQqrhYk7GiXgxHNeXwGBzftw==';
        
	      return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + publicKey + "</" + prefix + "X509Certificate></" + prefix + "X509Data>"
	  }
	  this.getKey = function(keyInfo) {
	    //you can use the keyInfo parameter to extract the key in any way you want      
	    return fs.readFileSync("public/cert.cer")
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
  sig.signingKey = fs.readFileSync("public/dsaprivkey.pem");
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

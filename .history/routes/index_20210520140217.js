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
  var privatekey = fs.readFileSync('public/privatekey.key');
  var cert = fs.readFileSync('public/cert.crt');
  
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
        
        var publicKey = 'MIIDcDCCAligAwIBAgIUGPgD0j5NPY1mTIkVLkuSRiD6ksUwDQYJKoZIhvcNAQELBQAwNzELMAkGA1UEBhMCSU4xFzAVBgNVBAgMDk1hZGh5YSBQcmFkZXNoMQ8wDQYDVQQHDAZCaG9wYWwwHhcNMjEwNTE5MTgzMDA1WhcNMzEwNTE3MTgzMDA1WjA3MQswCQYDVQQGEwJJTjEXMBUGA1UECAwOTWFkaHlhIFByYWRlc2gxDzANBgNVBAcMBkJob3BhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANvYa3HwkrSewshMlsif6FBfIg7UbUZ40wxK2YomWoMeOyA0RUUojgmEtaLsRgRrUrBEs2N4aA0CeFnALSGBYhxn30y3grtDA8laJIXfy+wA5yLws0cgrZyEQsHOlEXLNM1wxmHU1AgkcFBdEuJIVl2EcjDlbORqTI/NuuYWspufYWiTlcje7jEPelyPaPif605Z8+g1RdcofXO8/1J/4EW+8Klq+Z4VNirS/hFIDyvBn2SwJZGwt2ITv1oz0DkTUtpUidiJzRL9Pj7E9TdDU/fXAdFOyl9xq5nN43YtVtzGM5iKhL2LaaKaYkDYrXIHaXsU32pFaRGxGsReA0NKte8CAwEAAaN0MHIwHQYDVR0OBBYEFJoeDO6lO3YJRKkQnjgQS8WBNEQ6MB8GA1UdIwQYMBaAFJoeDO6lO3YJRKkQnjgQS8WBNEQ6MA4GA1UdDwEB/wQEAwIFoDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBAFGjjok7vkLfYYjpCzR6iS1uWRWKW5rOOB0gLSvwhSh7DidMIYSTQKX1KN8J1phHY5lGpgCrbz3A2u55JhAmr6usSo6s219bgfGk1IcYrR9ieeMMUIaTr2wiLDyIMOqUJ9C38dKkLLiv+1VL8/m0tB88Wj6v7fYsyQqIbfKpVkowrZaKDVhQVZsyh1FVUKDnhBFXomUx4aQRNbY4LVYkwKRkst5DFS5RYFbs5j0MWV3GwtDhB3cDt5b3wNoyYmmyvv3uTBjaU2W3TDRXbwP8ENqvcbjnZlOCuMWgECDg3NZvucrPIcUdroaeKUQJNuIDTcuBpUO+vCU+Eg7Qf3HJOkQ=';
        
	      return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + publicKey + "</" + prefix + "X509Certificate></" + prefix + "X509Data>"
	  }
	  this.getKey = function(keyInfo) {
	    //you can use the keyInfo parameter to extract the key in any way you want      
	    return fs.readFileSync("public/cert.crt")
	  }
	}

  var sig = new SignedXml();
  sig.addReference("//*[local-name(.)='Response']");
  sig.signingKey = fs.readFileSync("public/privatekey.key");
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

  const data = JSON.stringify({
    'SAMLResponse': base64Str,
    'idpConfig.recipient' : 'https://' + url + '/?so=00D7F000002CITw',
    'RelayState' : ''
  });
  
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
      'Content-Length': data.length
    }
  }
  
  const request = https.request(options, response => {
    console.log(`statusCode: ${response.statusCode}`)
  
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

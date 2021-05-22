require('dotenv').config();
var express = require('express');
var fs = require('fs');
var SignedXml = require('xml-crypto').SignedXml;
var select = require('xml-crypto').xpath;
var https = require('https');
var httpsproxyagent = require('https-proxy-agent');
var querystring = require('querystring');
var builder = require('xmlbuilder');
var router = express.Router();

//saml config values
var entity = "" + process.env.entity ;
var issuer = "" + process.env.issuer ;

//login endpoint
var login_url =  "" + process.env.login_url ;

//saml data values
var userFID = "" + process.env.userFID ;
var oId = "" + process.env.oId ;
var pId = "" + process.env.pId ;
var isPortal = "" + process.env.isPortal;
var accountname = "" + process.env.accountname;
var accountnumber = "" + process.env.accountnumber;
var contactemail = "" + process.env.contactemail;
var contactfname = "" + process.env.contactfname;
var contactlname = "" + process.env.contactlname;

//proxy setting
var isProxy = false;
var proxy_url = "";
var proxy_port = "";
var proxy_username = "";
var proxy_password = "";

//local varaibles
var base64Str = "";
var rawStr = "";
var data = "";
var error = "";

/* GET home page. */
router.get('/', function(req, res, next) {
  getReq_Process(req, res, next);
  
  return res.render('index', { title: '', rawStr : rawStr, base64Str : base64Str , login_url : login_url , data: data , error : error, 
            entity : entity, issuer : issuer, userFID : userFID, oId : oId, pId : pId, isPortal : isPortal,
            accountname : accountname, accountnumber : accountnumber, 
            contactemail : contactemail, contactfname : contactfname, contactlname : contactlname}
            );
});

router.post('/', function(req, res, next) {
  isPortal = req.body.isPortal;
  console.log(isPortal + ' >> ' + typeof isPortal);
  
  if(req.body.submit_action == "generate"){
    login_url = req.body.login_url;
    data = req.body.data;
    error = req.body.error;
    entity = req.body.entity;
    issuer = req.body.issuer;
    userFID = req.body.userFID;
    oId = req.body.oId;
    pId = req.body.pId;

    return res.redirect('/');
  }

  var data = {
    SAMLResponse: base64Str
  };

  var list = login_url.replace("https://" , "").split("/");
  var baseurl = list.shift();
  var path = list.join("/");

  const options = {
    hostname: baseurl,
    port: 443,
    path: '/' + path,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  }

  if(isProxy){
    var proxyServer = {
      host : proxy_url ,
      port : proxy_port ,
      protocol : 'http'
    };

    if(proxy_username != "" && proxy_password != ""){
      proxyServer.headers = {'Proxy-Authentication': 'Basic ' + new Buffer(proxy_username + ":" + proxy_password).toString('base64')};
    }

    var proxy = new httpsproxyagent(proxyServer);
    options.agent = proxy;

    console.log(proxyServer);
    console.log(proxy);
  }
  
  const request = https.request(options, response => {
    
    console.log(`statusCode: ${response.statusCode}`);

    if(response.statusCode > 300 && response.statusCode < 400){
      //console.log("redirect URL : " + response.headers.location);
      console.log('HEADERS: ' + JSON.stringify(response.headers));
      return res.redirect(response.headers.location);
    }

    response.on('data', d => {
      process.stdout.write(d);
      data = d;
      return res.render('index', { title: '', rawStr : rawStr, base64Str : base64Str , login_url : login_url , data: data , error : error, 
            entity : entity, issuer : issuer, userFID : userFID, oId : oId, pId : pId, isPortal : isPortal,
            accountname : accountname, accountnumber : accountnumber, 
            contactemail : contactemail, contactfname : contactfname, contactlname : contactlname}
            );
    });
  });
  
  request.on('error', err => {
    console.error(err);
    error = err;
    return res.render('index', { title: '', rawStr : rawStr, base64Str : base64Str , login_url : login_url , data: data , error : error, 
            entity : entity, issuer : issuer, userFID : userFID, oId : oId, pId : pId, isPortal : isPortal,
            accountname : accountname, accountnumber : accountnumber, 
            contactemail : contactemail, contactfname : contactfname, contactlname : contactlname}
            );
  });
  
  request.write(querystring.stringify(data));
  request.end();
});

function getReq_Process(req, res, next){
  var dtF = new Date(new Date().getTime() + (5 * 60000));
  var dtP = new Date(new Date().getTime() - (5 * 60000));
  var reqId = new Date().getTime();
  var assertionId = new Date().getTime();
  
  var xml = builder.create('saml2p:Response',{ encoding: 'utf-8' })
	.att('xmlns:saml2p', 'urn:oasis:names:tc:SAML:2.0:protocol')
	.att('xmlns:xs', 'http://www.w3.org/2001/XMLSchema')
	.att('Destination', entity)
	.att('ID', '_r-' + reqId)
	.att('IssueInstant', dtP.toISOString())
	.att('Version', "2.0")
.ele('saml2:Issuer' , issuer)
	.att('xmlns:saml2', "urn:oasis:names:tc:SAML:2.0:assertion")
.up()
.ele('saml2p:Status')
	.ele('saml2p:StatusCode')
		.att('Value', "urn:oasis:names:tc:SAML:2.0:status:Success")
	.up()
.up()
.ele('saml2:Assertion')
	.att('xmlns:saml2', "urn:oasis:names:tc:SAML:2.0:assertion")
	.att('ID', '_a-' + assertionId)
	.att('IssueInstant', dtP.toISOString())
	.att('Version', "2.0")
	.ele('saml2:Issuer' , issuer)
	.up()
	.ele('saml2:Subject')
		.ele('saml2:NameID', userFID)
			.att('Format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified')
		.up()
		.ele('saml2:SubjectConfirmation')
			.att('Method', 'urn:oasis:names:tc:SAML:2.0:cm:bearer')
			.ele('saml2:SubjectConfirmationData')
				.att('NotOnOrAfter', dtF.toISOString())
				.att('Recipient', entity)
			.up()
		.up()
	.up()
	.ele('saml2:Conditions')
		.att('NotBefore', dtP.toISOString())
		.att('NotOnOrAfter', dtF.toISOString())
		.ele('saml2:AudienceRestriction')
			.ele('saml2:Audience' , entity)
		.up()
	.up()
.up()
.ele('saml2:AuthnStatement')
	.att('AuthnInstant', dtP.toISOString())
	.ele('saml2:AuthnContext')
		.ele('saml2:AuthnContextClassRef' , 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified')
		.up()
	.up()
.up()
.ele('saml2:AttributeStatement')
	.ele('saml2:Attribute')
		.att('Name', 'ssoStartPage')
		.att('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified')
		.ele('saml2:AttributeValue' , issuer + '/sso')
			.att('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
			.att('xsi:type', 'xs:string')
		.up()
	.up()
	.ele('saml2:Attribute')
		.att('Name', 'logoutURL')
		.att('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified')
		.ele('saml2:AttributeValue')
			.att('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
			.att('xsi:type', 'xs:string')
		.up()
	.up();

  if(isPortal || isPortal == 'true'){
    xml = xml
      .ele('saml2:Attribute')
        .att('Name', 'organization_id')
        .att('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified')
        .ele('saml2:AttributeValue', oId)
          .att('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
          .att('xsi:type', 'xs:string')
        .up()
      .up()
      .ele('saml2:Attribute')
        .att('Name', 'portal_id')
        .att('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified')
        .ele('saml2:AttributeValue' , pId)
          .att('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
          .att('xsi:type', 'xs:string')
        .up()
      .up()
      .ele('saml2:Attribute')
        .att('Name', 'Account.Name')
        .att('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified')
        .ele('saml2:AttributeValue' , accountname)
          .att('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
          .att('xsi:anyType', 'xs:string')
        .up()
      .up()
      .ele('saml2:Attribute')
        .att('Name', 'Account.AccountNumber')
        .att('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified')
        .ele('saml2:AttributeValue' , accountnumber)
          .att('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
          .att('xsi:anyType', 'xs:string')
        .up()
      .up()
      .ele('saml2:Attribute')
        .att('Name', 'Contact.Email')
        .att('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified')
        .ele('saml2:AttributeValue' , contactemail)
          .att('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
          .att('xsi:anyType', 'xs:string')
        .up()
      .up()
      .ele('saml2:Attribute')
        .att('Name', 'Contact.FirstName')
        .att('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified')
        .ele('saml2:AttributeValue' , contactfname)
          .att('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
          .att('xsi:anyType', 'xs:string')
        .up()
      .up()
      .ele('saml2:Attribute')
        .att('Name', 'Contact.LastName')
        .att('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified')
        .ele('saml2:AttributeValue' , contactlname)
          .att('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
          .att('xsi:anyType', 'xs:string')
        .up()
      .up()

    .up()
    .up()
    .end({ pretty: false});
  }
  else{
    xml = xml
    .up()
    .up()
    .end({ pretty: false});
  }

  var message = xml.toString();

  /*message = message.replace(/TIMEGRT/g , dtF.toISOString());
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
	    return fs.readFileSync("public/rsa/rsa256/cert.cer");
	  }
	}

  var sig = new SignedXml();
  sig.addReference("//*[local-name(.)='Response']", ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"], ["http://www.w3.org/2000/09/xmldsig#sha1"]);
  sig.signingKey = fs.readFileSync("public/rsa/rsa256/privkey.pem");
  sig.keyInfoProvider = new MyKeyInfo();
  sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
  
  sig.computeSignature(message.toString(),{
    prefix: 'ds'
  });
  
  var saml = sig.getSignedXml();
  rawStr = saml.toString();
  base64Str = new Buffer(rawStr).toString('base64');
}

module.exports = router;

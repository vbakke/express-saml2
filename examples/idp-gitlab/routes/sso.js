var express = require('express');
var uuid = require('uuid');
var router = express.Router();
var fs = require('fs');
var utility = require('../../../index').Utility;
var SamlLib = require('../../../index').SamlLib;
var binding = require('../../../index').Constants.wording.binding;
var spSet = [];
var epn = {
  'admin@idp.com': {
    assoHash: '$2a$10$/0lqAmz.r6trTurxW3qMJuFHyicUWsV3GKF94KcgN42eVR8y5c25S',
    app: {
      'gitlab': {
        assoSpEmail: 'admin@example.com',
        assoName: 'Administrator',
        assoFirst: '',
        assoLast: ''
      }
    }
  }
};

/// Declare that entity, and load all settings when server is started
/// Restart server is needed when new metadata is imported
var idp1 = require('../../../index').IdentityProvider({
  privateKeyFile: './misc/privkey.pem',
  isAssertionEncrypted: false,
  privateKeyFilePass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  generateID: () => {
    const id = uuid.v4();
    console.log('[debug] generateID', id);
    return `_${id}`;
  },
  loginResponseTemplate: '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{IssueInstant}"> <saml:AuthnContext><saml:AuthnContextClassRef>AuthnContextClassRef</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue>{attrUserEmail}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue>{attrUserName}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="first_name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue>{attrUserFirst}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="last_name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue>{attrUserLast}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>'
}, './misc/metadata_idp1.xml');

/// Declare the sp
var sp1 = require('../../../index').ServiceProvider('./misc/metadata_sp1.xml');

/// metadata is publicly released, can access at /sso/metadata
router.get('/metadata/:id', function (req, res, next) {
  var entity = entityPair(req.params.id);
  var assoIdp = entity.assoIdp;
  res.header('Content-Type', 'text/xml').send(assoIdp.getMetadata());
});

spSet.push(sp1);

function entityPair(id) {
  var targetSP, assoIdp;
  switch (id.toString()) {
    case 'gitlab':
      targetSP = sp1;
      assoIdp = idp1;
      break;
    default:
      break;
  }
  return {
    targetSP: targetSP,
    assoIdp: assoIdp
  };
}

router.all('/:action/:id', function (req, res, next) {
  if (!req.isAuthenticated()) {
    var url = '/login';
    if (req.params && req.params.action == 'SingleSignOnService') {
      if (req.method.toLowerCase() == 'post') {
        url = '/login/external.esaml?METHOD=post&TARGET=' + utility.base64Encode(JSON.stringify({
          entityEndpoint: req.originalUrl,
          actionType: 'SAMLRequest',
          actionValue: req.body.SAMLRequest,
          relayState: req.body.relayState
        }));
      } else if (req.method.toLowerCase() == 'get') {
        url = '/login/external.esaml?METHOD=get&TARGET=' + utility.base64Encode(req.originalUrl);
      }
    } else if (req.params && req.params.action == 'SingleLogoutService') {
      if (req.method.toLowerCase() == 'post') {
        url = '/logout/external.esaml?METHOD=post&TARGET=' + utility.base64Encode(JSON.stringify({
          entityEndpoint: req.originalUrl,
          actionType: 'LogoutRequest',
          actionValue: req.body.LogoutRequest,
          relayState: req.body.relayState
        }));
      } else if (req.method.toLowerCase() == 'get') {
        url = '/logout/external.esaml?METHOD=get&TARGET=' + utility.base64Encode(req.originalUrl);
      }
    } else {
      // Unexpected error
      console.warn('Unexpected error');
    }
    return res.redirect(url);
  }
  next();
});

const tagReplacement = (req, targetSP, assoIdp) => template => {
  const user = epn[req.user.sysEmail].app[req.params.id.toString()];
  var now = new Date();
  var spEntityID = targetSP.entityMeta.getEntityID();
  var idpSetting = assoIdp.entitySetting;
  var fiveMinutesLater = new Date(now.getTime());
  fiveMinutesLater.setMinutes(fiveMinutesLater.getMinutes() + 5);
  var fiveMinutesLater = new Date(fiveMinutesLater).toISOString();
  var now = now.toISOString();
  var tvalue = {
    ID: `_${uuid.v4()}`,
    AssertionID: idpSetting.generateID ? idpSetting.generateID() : `_${uuid.v4()}`,
    Destination: targetSP.entityMeta.getAssertionConsumerService(binding.post),
    Audience: spEntityID,
    SubjectRecipient: spEntityID,
    NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    NameID: req.user.email,
    Issuer: assoIdp.entityMeta.getEntityID(),
    IssueInstant: now,
    ConditionsNotBefore: now,
    ConditionsNotOnOrAfter: fiveMinutesLater,
    SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater,
    AssertionConsumerServiceURL: targetSP.entityMeta.getAssertionConsumerService(binding.post),
    EntityID: spEntityID,
    StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
    // YOUR ATTRIBUTE CAN BE FILLED IN RUN TIME
    attrUserEmail: user.assoSpEmail,
    attrUserName: user.assoName,
    attrUserFirst: user.assoFirst,
    attrUserLast: user.assoLast
  };
  response = SamlLib.replaceTagsByValue(template, tvalue);
  // replace tag
  console.log('*******************', response);
  return response;
};

router.get('/SingleSignOnService/:id', function (req, res) {
  var entity = entityPair(req.params.id);
  var assoIdp = entity.assoIdp;
  var targetSP = entity.targetSP;
  assoIdp.parseLoginRequest(targetSP, 'redirect', req, function (parseResult) {
    const user = epn[req.user.sysEmail].app[req.params.id.toString()];
    req.user.email = user.assoSpEmail;
    console.log('[debug] ready to send response, request is redirect binding');
    assoIdp.sendLoginResponse(targetSP, parseResult, 'post', req.user, function (response) {
      console.log('[debug] render and prepare for a POST request, response is', response);
      fs.writeFileSync('./response.xml', response.actionValue);
      res.render('actions', response);
    }, tagReplacement(req, targetSP, assoIdp));
  });
});

router.post('/SingleSignOnService/:id', function (req, res) {
  var entity = entityPair(req.params.id);
  var assoIdp = entity.assoIdp;
  var targetSP = entity.targetSP;
  assoIdp.parseLoginRequest(targetSP, 'post', req, function (parseResult) {
    const user = epn[req.user.sysEmail].app[req.params.id.toString()];
    req.user.email = user.assoSpEmail;
    return assoIdp.sendLoginResponse(targetSP, parseResult, 'post', req.user, function (response) {
      return res.render('actions', response);
    }, tagReplacement(req, targetSP, assoIdp));
  });
});

router.get('/SingleLogoutService/:id', function (req, res) {
  var entity = entityPair(req.params.id);
  var assoIdp = entity.assoIdp;
  var targetSP = entity.targetSP;
  assoIdp.parseLogoutResponse(targetSP, 'redirect', req, function (parseResult) {
    if (req.query.RelayState) {
      res.redirect(req.query.RelayState);
    } else {
      req.logout();
      req.flash('info', 'All participating service provider has been logged out');
      res.redirect('/login');
    }
  });
});

router.post('/SingleLogoutService/:id', function (req, res) {
  var entity = entityPair(req.params.id);
  var assoIdp = entity.assoIdp;
  var targetSP = entity.targetSP;
  assoIdp.parseLogoutResponse(targetSP, 'post', req, function (parseResult) {
    if (req.body.RelayState) {
      res.redirect(req.body.RelayState);
    } else {
      delete req.session.relayStep;
      req.logout();
      req.flash('info', 'All participating service provider has been logged out');
      res.redirect('/login');
    }
  });
});

router.get('/logout/all', function (req, res) {
  var serviceList = Object.keys(epn[req.user.sysEmail].app);
  var relayState = 'http://localhost:3001/sso/logout/all';
  var relayStep = req.session.relayStep;
  if (relayStep !== undefined && relayStep + 1 !== serviceList.length) {
    req.session.relayStep = parseInt(relayStep) + 1;
  } else {
    req.session.relayStep = 0;
  }
  if (req.session.relayStep < serviceList.length) {
    if (req.session.relayStep === serviceList.length - 1) {
      relayState = '';
    }
    var id = serviceList[req.session.relayStep];
    var entity = entityPair(id);
    var assoIdp = entity.assoIdp;
    var targetSP = entity.targetSP;
    const user = epn[req.user.sysEmail].app[req.params.id.toString()];
    req.user.email = user.assoSpEmail;
    assoIdp.sendLogoutRequest(targetSP, 'post', req.user, relayState, function (response) {
      if (req.query && req.query.async && req.query.async.toString() === 'true') {
                response.ajaxSubmit = true;
            }
            res.render('actions', response);
        });
    } else {
        req.logout();
        req.flash('info', 'Unexpected error in /relayState');
        res.redirect('/login');
    }
});

router.get('/select/:id', function (req, res) {
    var entity = entityPair(req.params.id);
    var assoIdp = entity.assoIdp;
    var targetSP = entity.targetSP;
    const user = epn[req.user.sysEmail].app[req.params.id.toString()];
    req.user.email = user.assoSpEmail;
    assoIdp.sendLoginResponse(targetSP, null, 'post', req.user, function (response) {
        response.title = 'POST data';
        res.render('actions', response);
    }, tagReplacement(req, targetSP, assoIdp));
});

module.exports = router;

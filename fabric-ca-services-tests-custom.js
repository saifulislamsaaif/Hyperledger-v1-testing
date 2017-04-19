/**
 * Copyright 2016 IBM All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
'use strict';

if (global && global.hfc) global.hfc.config = undefined;
require('nconf').reset();
var utils = require('fabric-client/lib/utils.js');
utils.setConfigSetting('hfc-logging', '{"debug":"console"}');
var logger = utils.getLogger('fabric-ca-services');

var tape = require('tape');
var _test = require('tape-promise');
var test = _test(tape);


var hfc = require('fabric-client');

var X509 = require('jsrsasign').X509;

var util = require('util');
var fs = require('fs');
var path = require('path');
var testUtil = require('../unit/util.js');
var LocalMSP = require('fabric-client/lib/msp/msp.js');
var idModule = require('fabric-client/lib/msp/identity.js');
var SigningIdentity = idModule.SigningIdentity;
var Signer = idModule.Signer;
var User = require('fabric-client/lib/User.js');

var keyValStorePath = testUtil.KVS;

var FabricCAServices = require('fabric-ca-client/lib/FabricCAClientImpl');
var FabricCAClient = FabricCAServices.FabricCAClient;

//var enrollmentID = 'testUser';
var enrollmentID = 'user7';
var secondAdmin = 'admin7';

var enrollmentSecret;
var csr = fs.readFileSync(path.resolve(__dirname, '../fixtures/fabricca/enroll-csr.pem'));

hfc.addConfigFile(path.join(__dirname, 'e2e', 'config.json'));
var ORGS = hfc.getConfigSetting('test-network');
var userOrg = 'org1';

var	tlsOptions = {
	trustedRoots: [],
	verify: false
};
var fabricCAEndpoint = ORGS[userOrg].ca;

/**
 * FabricCAServices class tests
 */

//run the enroll test

test('FabricCAServices: Test enroll() With Dynamic CSR', function (t) {

	var caService = new FabricCAServices(fabricCAEndpoint, tlsOptions, {keysize: 256, hash: 'SHA2'});

	var req = {
		enrollmentID: 'admin',
		enrollmentSecret: 'adminpw'
	};

	var eResult, client, member, webAdmin;
	return caService.enroll(req)
		.then((enrollment) => {
			t.pass('Successfully enrolled \'' + req.enrollmentID + '\'.');
			eResult = enrollment;

			//check that we got back the expected certificate
			//var cert = new X509();
			//cert.readCertPEM(enrollment.certificate);
			//t.comment(cert.getSubjectString());
			//t.equal(cert.getSubjectString(), '/CN=' + req.enrollmentID, 'Subject should be /CN=' + req.enrollmentID);

			//return caService.cryptoPrimitives.importKey(enrollment.certificate);

			member = new User(secondAdmin);
			return member.setEnrollment(eResult.key, eResult.certificate, 'Org1MSP');			
		},(err) => {
			t.fail('Failed to enroll the admin. Can not progress any further. Exiting. ' + err.stack ? err.stack : err);

			t.end();
		}).then(() => {			
			return caService.register({enrollmentID: enrollmentID, role: 'client', affiliation: 'org2.department1'}, member);
		}).then((secret) => {
			t.comment(secret);		
		});
});

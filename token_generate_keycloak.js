#!/bin/env node

const axios = require('axios');
const jwt   = require('jsonwebtoken');
const base64 = require('base64url');
const qstring = require('querystring')
require('dotenv').config()

BASE_KEYCLOAK_URL='https://localhost:7000'  //provided we port forward the keycloak-ui-svc service via command: kubectl port-forward svc/keycloak-ui-svc 7000:443

class Token{
    constructor(realm){
	this.REALM = realm
	this.PUBLIC_KEY_ENDPOINT=`${BASE_KEYCLOAK_URL}/auth/realms/${this.REALM}`	
	this.JWT_TOKEN_ENDPOINT=`${BASE_KEYCLOAK_URL}/auth/realms/${this.REALM}/protocol/openid-connect/token`

	console.log(`TLS variable value to override https check is:${process.env.NODE_TLS_REJECT_UNAUTHORIZED}`)
    }

    async fetch_public_key(){
	try {
	    console.log(this.PUBLIC_KEY_ENDPOINT)
	    const response = await axios.get(this.PUBLIC_KEY_ENDPOINT);
	    return response.data.public_key
	} catch (error) {
	    console.error(error);
	}
    }

    async fetch_jwt_token(username, password, client_id, client_secret){
	var packet = {
	    "token_type_hint":"access_token",	    
	    "client_id": client_id,
	    "client_secret": client_secret,
	    "username": username,
	    "password": password,
	    "grant_type":"password"
	}

	var config = {
            headers: {'Content-Type': 'application/x-www-form-urlencoded'}
	}

	try{
	    console.log(packet)
	    const response = await axios.post( this.JWT_TOKEN_ENDPOINT, qstring.stringify(packet), config);
	    console.log(response)
	    return response
	}
	catch(err) {
	    console.error(err);
	}
	//Question: What sort of grant type do we use to get the token ?
    }

    async sign_token_using_hsm(token){
	
    }

    async verify_jwt_token(jwt_token){
	const crypto = require('crypto');
	const verifyFunction = crypto.createVerify('RSA-SHA256');
	
	let public_key = await this.fetch_jwt_token()
	
	const jwtHeader = jwt_token.split('.')[0];
	const jwtPayload = jwt_token.split('.')[1];
	const jwtSignature = jwt_token.split('.')[2];

	verifyFunction.write(jwtHeader + '.' + jwtPayload);
	verifyFunction.end();

	const jwtSignatureBase64 = base64.toBase64(jwtSignature);
	const signatureIsValid = verifyFunction.verify(PUB_KEY, jwtSignatureBase64, 'base64');
	jwt.verify(token, jwtKey)
    }
    
}


if (require.main == module){

    (async () => {

	//test the fetching of public key
	REALM = 'Ambidexter'
	t = new Token(REALM)
	console.log(await t.fetch_public_key())

	//Now testing getting of jwt from a keycloak instance
	let token = await t.fetch_jwt_token(process.env.USERNAME, process.env.PASSWORD, process.env.CLIENT_ID, process.env.CLIENT_SECRET)
	console.log(token)
	
    })();
    
}

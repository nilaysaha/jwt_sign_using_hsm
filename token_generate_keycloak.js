#!/bin/env node

const axios = require('axios');
const jwt   = require('jsonwebtoken');
const base64 = require('base64url');

BASE_KEYCLOAK_URL='http://localhost:7000'  //provided we port forward the keycloak-ui-svc service via command: kubectl port-forward svc/keycloak-ui-svc 7000:443

class Keycloak{
    constructor(realm){
	this.REALM = realm
	this.PUBLIC_KEY_ENDPOINT=`${BASE_KEYCLOAK_URL}/auth/realms/${this.REALM}`	
	this.JWT_TOKEN_ENDPOINT=`${BASE_KEYCLOAK_URL}/auth/realms/${this.REALM}/protocol/openid-connect/token`
    }

    async fetch_public_key(){
	try {
	    const response = await axios.get(this.PUBLIC_KEY_ENDPOINT);
	    console.log(response);
	    return response
	} catch (error) {
	    console.error(error);
	}
    }

    async fetch_jwt_token(username, password, client_id){
	var packet = {
	    "username": username,
	    "password": password,
	    "client_id": client_id,
	    "grant_type": password
	}

	try{
	    const response = await axios.post( this.JWT_TOKEN_ENDPOINT, packet);
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

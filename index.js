const axios = require('axios').default;
const jose = require("jose");
const crypto = require('crypto');
const jwt_decode = require('jwt-decode');

const CLIENT_PRIVATE_KEY = `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBcFk+pUgf7/l97wnmiSLNgIYxvZAb8ikUGnXZaK+Laudlaed/ybPY
aIsDbDZ/CbFVEjRPAt05jnH2mYqtGvoZD3GgBwYFK4EEACOhgYkDgYYABACUaWpQ
anIYzsbcEP/NDDT8/v5/il/5BvRTX/0MBAgYOfVSovZyRfcB+yBWSfVpaO+On9ls
oLVNm/LwUEPRn+OngwBsyETZARPUO8zIfJBAlDpH7cfzGigqH9aL9Sjtk5YzOWlX
D3yJEcVrAbVEpG/Z58A2jvEm272IUUyN9lKGVaTp1A==
-----END EC PRIVATE KEY-----`;

const API_KEY = '9542a700-71d9-46cc-bcfa-58733d62bc69';

const QI_AUTH_ADDRESS = 'https://api-auth.sandbox.qitech.app';

function validateApiKey(apiKey) {
    if (apiKey !== API_KEY) {
        throw new Error("The api_key does not match the one provided to the function");
    }
}

async function qi_sign_message(endpoint, method, body=null, content_type="", additional_headers=null) {
    let privateKey = CLIENT_PRIVATE_KEY;

    privateKey = crypto.createPrivateKey({
        key: privateKey,
        format: "pem",
        type: "pkcs1",
        passphrase: "",
        encoding: "utf-8"
    });

    let md5_body = '';
    let request_body = null;

    let now = new Date();
    let formated_date = now.toUTCString();

    if(body) {
        const encoded_body_token = await new jose.SignJWT(body)
            .setProtectedHeader({ alg: 'ES512' })
            .sign(privateKey);

        request_body = {"encoded_body": encoded_body_token};

        md5_body = crypto.createHash('md5').update(encoded_body_token).digest('hex');
    }

    const string_to_sign = (
        method + "\n" + md5_body + "\n" + content_type + "\n" + formated_date + "\n" + endpoint
    );

    const headers = {"alg": "ES512", "typ": "JWT"};
    const claims = {"sub": API_KEY, "signature": string_to_sign};

    const encoded_header_token = await new jose.SignJWT(claims)
        .setProtectedHeader({ alg: 'ES512' })
        .setProtectedHeader(headers)
        .sign(privateKey);

    const authorization = "QIT" + " " + API_KEY + ":" + encoded_header_token;

    let request_header = {"AUTHORIZATION": authorization, "API-CLIENT-KEY": API_KEY};

    if (additional_headers) {
        request_header.update(additional_headers);
    }

    return {request_header, request_body};
};

async function qi_translate_message(endpoint, method, response_body, response_header=null) {
    const body = await jwt_decode(response_body['encoded_body']);

    const authorization = response_header["authorization"];
    const header_api_key = response_header["api-client-key"];

    validateApiKey(header_api_key);

    const split_authorization = authorization.split(":");

    let authorization_api_key = split_authorization[0].split(" ")[1];

    validateApiKey(authorization_api_key);

    const  header_token = split_authorization[1];
    const decoded_header_token = await jwt_decode(header_token);

    const signature = decoded_header_token["signature"];
    const split_signature = signature.split("\n");
    const signature_method = split_signature[0];
    const signature_md5_body = split_signature[1];
    const signature_date = split_signature[3];
    const signature_endpoint = split_signature[4];

    if (signature_endpoint !== endpoint) {
        throw new Error("The endpoint gathered on message's authorization header does not match the one provided to the function");
    }

    if (signature_method !== method) {
        throw new Error("The method gathered on message's authorization header does not match the one provided to the function");
    }

    const md5_body = crypto.createHash('md5').update(response_body["encoded_body"]).digest('hex');

    if (signature_md5_body !== md5_body) {
        throw new Error("The 'md5_body' parameter gathered on message's signature does not match the 'body' provided to the function");
    }

    return body;
};

async function post_request(endpoint, method, body, content_type) {
    const url = `${QI_AUTH_ADDRESS}${endpoint}`;

    const signed_request = await qi_sign_message(endpoint, method, body);

    const request_config = {
        headers: signed_request.request_header
    };

    try {
        const response = await axios.post(url, signed_request.request_body, request_config);
        return await qi_translate_message(endpoint, method, response.data, response.headers);
    } catch (error) {
        console.error(error);
        throw error;
    }
};

async function main() {
    const endpoint = `/test/${API_KEY}`;
    const method = "POST";
    const body = {"name": "QI Tech"};
    const content_type = "application/json";

    try {
        const response = await post_request(endpoint, method, body, content_type);
        console.log(response);
    } catch (error) {
        console.error('Error in main:', error);
    }
}

main().catch(error => console.error('Error in main:', error));

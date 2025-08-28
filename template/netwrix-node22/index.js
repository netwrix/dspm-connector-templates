"use strict"

const express = require('express')
const app = express()
const handler = require('./function/handler');
const bodyParser = require('body-parser')
const fs = require('fs').promises
const path = require('path')
const { validateRequestSchema, validateResponse, validateDevData, validateUpdateExecutionParams } = require('./local_testing')

const defaultMaxSize = '100kb' // body-parser default

app.disable('x-powered-by');

const rawLimit = process.env.MAX_RAW_SIZE || defaultMaxSize
const jsonLimit = process.env.MAX_JSON_SIZE || defaultMaxSize

app.use(function addDefaultContentType(req, res, next) {
    // When no content-type is given, the body element is set to 
    // nil, and has been a source of contention for new users.

    if(!req.headers['content-type']) {
        req.headers['content-type'] = "text/plain"
    }
    next()
})

if (process.env.RAW_BODY === 'true') {
    app.use(bodyParser.raw({ type: '*/*' , limit: rawLimit }))
} else {
    app.use(bodyParser.text({ type : "text/*" }));
    app.use(bodyParser.json({ limit: jsonLimit}));
    app.use(bodyParser.urlencoded({ extended: true }));
}

const isArray = (a) => {
    return (!!a) && (a.constructor === Array);
};

const isObject = (a) => {
    return (!!a) && (a.constructor === Object);
};

class FunctionEvent {
    constructor(req) {
        this.body = req.body;
        this.headers = req.headers;
        this.method = req.method;
        this.query = req.query;
        this.path = req.path;
    }
}

class FunctionContext {
    constructor(cb) {
        this.statusCode = 200;
        this.cb = cb;
        this.headerValues = {};
        this.cbCalled = 0;
        
        // Netwrix-specific context properties
        this.hostname = process.env.HOSTNAME || 'localhost';
        this.secrets = null;
        this.scanId = process.env.SCAN_ID;
        this.syncId = process.env.SYNC_ID;
        this.scanExecutionId = null;
        this.syncExecutionId = null;
        this.runLocal = process.env.RUN_LOCAL || 'false';
        this.config = process.env.CONFIG ? JSON.parse(process.env.CONFIG) : null;
        this.functionType = process.env.FUNCTION_TYPE;
    }

    status(statusCode) {
        if(!statusCode) {
            return this.statusCode;
        }

        this.statusCode = statusCode;
        return this;
    }

    headers(value) {
        if(!value) {
            return this.headerValues;
        }

        this.headerValues = value;
        return this;    
    }

    succeed(value) {
        let err;
        this.cbCalled++;
        this.cb(err, value);
    }

    fail(value) {
        let message;
        if(this.status() == "200") {
            this.status(500)
        }

        this.cbCalled++;
        this.cb(value, message);
    }

    testConnectionSuccessResponse() {
        return {
            statusCode: 200,
            body: {}
        };
    }
    
    accessScanSuccessResponse() {
        return {
            statusCode: 200,
            body: {}
        };
    }
    
    getObjectSuccessResponse(data) {
        const encodedData = Buffer.from(data).toString('base64');
        
        return {
            statusCode: 200,
            body: { data: encodedData }
        };
    }

    errorResponse(clientError, errorMsg) {
        const statusCode = clientError ? 400 : 500;

        return {
            statusCode: statusCode,
            body: { error: errorMsg }
        };
    }
    
    async saveData(data) {
        // Add scan_id, scan_execution_id, and scanned_at to each row
        const enhancedData = [];
        const currentTime = new Date().toISOString();

        const localRun = this.runLocal === "true";
        const scanId = localRun ? "scan0001" : this.scanId;
        const scanExecutionId = localRun ? "scan-0002" : this.scanExecutionId;
        
        for (const row of data) {
            const enhancedRow = {
                scan_id: scanId,
                scan_execution_id: scanExecutionId,
                scanned_at: currentTime,
                ...row
            };
            enhancedData.push(enhancedRow);
        }
        
        // Dev environment validation
        if (localRun) {
            const { isValid, errorMsg } = validateDevData(this.config, enhancedData);
            if (!isValid) {
                console.log(errorMsg);
                return { success: false, error: errorMsg };
            } else {
                console.log(`Saving ${enhancedData.length} items to table`);
                if (enhancedData.length > 0) {
                    console.log(`Sample item: ${JSON.stringify(enhancedData[0], null, 2)}`);
                }
                return { success: true, error: null };
            }
        } else {
            const saveDataFunction = process.env.SAVE_DATA_FUNCTION;
            if (!saveDataFunction) {
                const errorMsg = "SAVE_DATA_FUNCTION is not in the environment";
                console.log(errorMsg);
                return { success: false, error: errorMsg };
            }
        
            try {
                const payload = {
                    sourceType: process.env.SOURCE_TYPE,
                    version: process.env.SOURCE_VERSION,
                    table: 'access',
                    data: enhancedData
                };
                
                const response = await fetch(
                    `${process.env.OPENFAAS_GATEWAY}/async-function/${saveDataFunction}`,
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    }
                );
                
                if (response.status === 202) {
                    return { success: true, error: null };
                } else {
                    const errorMsg = `Status ${response.status}: ${await response.text()}`;
                    console.log(errorMsg);
                    return { success: false, error: errorMsg };
                }
            } catch (e) {
                const errorMsg = `Error: ${e.message}`;
                console.log(errorMsg);
                return { success: false, error: errorMsg };
            }
        }
    }
    
    async updateExecution(status = null, totalObjects = null, completedObjects = null, incrementCompletedObjects = null, completedAt = null) {
        // Validation for dev environment
        if (this.runLocal === "true") {
            const { isValid, errorMsg } = validateUpdateExecutionParams(status, totalObjects, completedObjects, incrementCompletedObjects, completedAt);
            if (!isValid) {
                console.log(errorMsg);
                return { success: false, error: errorMsg };
            } else {
                return { success: true, error: null };
            }
        } else {
            const appUpdateFunction = process.env.APP_UPDATE_EXECUTION_FUNCTION;
            if (!appUpdateFunction) {
                const errorMsg = "APP_UPDATE_EXECUTION_FUNCTION is not in the environment";
                console.log(errorMsg);
                return { success: false, error: errorMsg };
            }
        
            let executionId, executionType;
            if (this.scanExecutionId) {
                executionId = this.scanExecutionId;
                executionType = 'scan';
            } else if (this.syncExecutionId) {
                executionId = this.syncExecutionId;
                executionType = 'sync';
            } else {
                const errorMsg = "Missing required field: either 'scanExecutionId' or 'syncExecutionId' must be provided";
                console.log(errorMsg);
                return { success: false, error: errorMsg };
            }
            
            try {
                // Build payload with only provided arguments
                const payload = {
                    type: executionType,
                    executionId: executionId
                };
                
                // Only include optional fields if they are provided (not null)
                if (status !== null) payload.status = status;
                if (totalObjects !== null) payload.totalObjects = totalObjects;
                if (completedObjects !== null) payload.completedObjects = completedObjects;
                if (incrementCompletedObjects !== null) payload.incrementCompletedObjects = incrementCompletedObjects;
                if (completedAt !== null) payload.completedAt = completedAt;
                
                const response = await fetch(
                    `${process.env.OPENFAAS_GATEWAY}/async-function/${appUpdateFunction}`,
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    }
                );
                
                if (response.status === 202) {
                    return { success: true, error: null };
                } else {
                    const errorMsg = `Status ${response.status}: ${await response.text()}`;
                    console.log(errorMsg);
                    return { success: false, error: errorMsg };
                }
            } catch (e) {
                const errorMsg = `Error: ${e.message}`;
                console.log(errorMsg);
                return { success: false, error: errorMsg };
            }
        }
    }
}

async function getSecrets(localRun = false) {
    const secrets = {};
    const secretsDir = '/var/openfaas/secrets/';
    
    try {
        const files = await fs.readdir(secretsDir);
        
        for (const filename of files) {
            const secretPath = path.join(secretsDir, filename);
            
            try {
                const stat = await fs.stat(secretPath);
                if (!stat.isFile()) continue;
            } catch (e) {
                continue;
            }
            
            // Extract the key name based on localRun parameter
            let keyName;
            if (localRun) {
                // For local run, use the filename as-is (no scan ID removal)
                keyName = filename;
            } else {
                // For non-local run, remove the last 9 characters (dash + 8 chars scan ID)
                if (filename.length > 9 && filename.charAt(filename.length - 9) === '-') {
                    keyName = filename.slice(0, -9); // Remove last 9 characters (-abcd1234)
                } else {
                    console.log(`Skipping secret file with unexpected format: ${filename}`);
                    continue;
                }
            }
            
            // Convert dash-separated to camelCase
            const keyParts = keyName.split('-');
            let camelKey;
            if (keyParts.length > 1) {
                // First part stays lowercase, subsequent parts are capitalized
                camelKey = keyParts[0] + keyParts.slice(1).map(word => 
                    word.charAt(0).toUpperCase() + word.slice(1)).join('');
            } else {
                camelKey = keyParts[0];
            }
            
            // Read the secret content
            try {
                const content = await fs.readFile(secretPath, 'utf8');
                secrets[camelKey] = content.trim();
                console.log(`Loaded secret: ${camelKey}`);
            } catch (e) {
                console.error(`Error reading secret file ${filename}: ${e.message}`);
            }
        }
    } catch (e) {
        console.error(`Error reading secrets directory: ${e.message}`);
    }
    
    return secrets;
}

const middleware = async (req, res) => {
    const cb = (err, functionResult) => {
        if (err) {
            console.error(err);

            return res.status(fnContext.status())
                .send(err.toString ? err.toString() : err);
        }

        if(isArray(functionResult) || isObject(functionResult)) {
            res.set(fnContext.headers())
                .status(fnContext.status()).send(JSON.stringify(functionResult));
        } else {
            res.set(fnContext.headers())
                .status(fnContext.status())
                .send(functionResult);
        }
    };

    const fnEvent = new FunctionEvent(req);
    const fnContext = new FunctionContext(cb);

    const localRun = fnContext.runLocal === "true";

    if (localRun) {
        if (!fnContext.config) {
            return res.status(400).json({ error: "CONFIG is required when RUN_LOCAL is true" });
        }
        
        if (!fnContext.functionType) {
            return res.status(400).json({ error: "FUNCTION_TYPE is required when RUN_LOCAL is true" });
        }
        
        try {
            // Validate request body against config
            let requestData = fnEvent.body;
            if (typeof requestData === 'string') {
                requestData = JSON.parse(requestData);
            }
            const { isValid, errorMsg } = validateRequestSchema(fnContext.config, requestData, fnContext.functionType);
            if (!isValid) {
                return res.status(400).json({ error: errorMsg });
            }
        } catch (e) {
            return res.status(400).json({ error: `Invalid JSON in request body: ${e.message}` });
        }
    }

    // Load secrets from OpenFaaS secret files
    fnContext.secrets = await getSecrets(localRun);

    // Parse execution IDs from request body
    try {
        let requestData = fnEvent.body;
        if (typeof requestData === 'string') {
            requestData = JSON.parse(requestData);
        }
        if (requestData.scanExecutionId) {
            fnContext.scanExecutionId = requestData.scanExecutionId;
        }
        if (requestData.syncExecutionId) {
            fnContext.syncExecutionId = requestData.syncExecutionId;
        }
    } catch (e) {
        // Ignore JSON parsing errors for execution IDs
    }

    if (Object.keys(fnContext.secrets).length === 0) {
        console.log("Warning: No secrets loaded from secret files");
    } else {
        console.log(`Loaded ${Object.keys(fnContext.secrets).length} secrets from secret files`);
    }

    const startedAt = new Date().toISOString();

    try {
        const responseData = await Promise.resolve(handler(fnEvent, fnContext, cb));
        
        if (!fnContext.cbCalled) {
            const completedAt = new Date().toISOString();

            console.log(`Response data: ${JSON.stringify(responseData)}`);

            let finalResponse = responseData;

            if (fnContext.functionType === "test-connection" && responseData?.statusCode === 200) {
                if (!responseData.body) responseData.body = {};
                responseData.body.startedAt = startedAt;
                responseData.body.completedAt = completedAt;
                finalResponse = responseData;
            } else if (fnContext.functionType === "access-scan" && responseData?.statusCode === 200) {
                if (!responseData.body) responseData.body = {};
                responseData.body.startedAt = startedAt;
                responseData.body.completedAt = completedAt;
                finalResponse = responseData;
            }

            if (localRun && finalResponse) {
                const { isValid, errorMsg } = validateResponse(fnContext.functionType, finalResponse);
                if (!isValid) {
                    finalResponse = fnContext.errorResponse(false, errorMsg);
                }
            }

            if (finalResponse?.statusCode) {
                res.status(finalResponse.statusCode);
            }

            if (finalResponse?.body) {
                return res.json(finalResponse.body);
            }

            fnContext.succeed(finalResponse);
        }
    } catch (e) {
        cb(e);
    }
};

app.post('/*', middleware);
app.get('/*', middleware);
app.patch('/*', middleware);
app.put('/*', middleware);
app.delete('/*', middleware);
app.options('/*', middleware);

const port = process.env.http_port || 3000;

app.listen(port, () => {
    console.log(`node22 listening on port: ${port}`)
});
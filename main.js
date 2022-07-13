"use strict";

/*
 * Created with @iobroker/create-adapter v1.34.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const axios = require("axios").default;
const Json2iob = require("./lib/json2iob");
const crypto = require("crypto");
const qs = require("qs");
const tough = require("tough-cookie");
const { HttpsCookieAgent } = require("http-cookie-agent/http");
const awsIot = require("aws-iot-device-sdk");

class Hoover extends utils.Adapter {
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    constructor(options) {
        super({
            ...options,
            name: "hoover",
        });
        this.on("ready", this.onReady.bind(this));
        this.on("stateChange", this.onStateChange.bind(this));
        this.on("unload", this.onUnload.bind(this));
        this.deviceArray = [];
        this.json2iob = new Json2iob(this);
        this.cookieJar = new tough.CookieJar();
        this.requestClient = axios.create({
            withCredentials: true,
            httpsAgent: new HttpsCookieAgent({
                cookies: {
                    jar: this.cookieJar,
                },
            }),
        });
    }

    /**
     * Is called when databases are connected and adapter received configuration.
     */
    async onReady() {
        // Reset the connection indicator during startup
        this.setState("info.connection", false, true);
        if (this.config.interval < 0.5) {
            this.log.info("Set interval to minimum 0.5");
            this.config.interval = 0.5;
        }
        if (!this.config.username || !this.config.password) {
            this.log.error("Please set username and password in the instance settings");
            return;
        }
        this.userAgent = "ioBroker v0.0.1";

        this.updateInterval = null;
        this.reLoginTimeout = null;
        this.refreshTokenTimeout = null;
        this.session = {};
        this.subscribeStates("*");

        await this.login();

        if (this.session.access_token) {
            await this.getDeviceList();
            await this.connectMqtt();
            await this.updateDevices();
            this.updateInterval = setInterval(async () => {
                await this.updateDevices();
            }, 10 * 60 * 1000);
            this.refreshTokenInterval = setInterval(() => {
                this.refreshToken();
            }, 2 * 60 * 60 * 1000);
        }
    }
    async login() {
        const initUrl = await this.requestClient({
            method: "get",
            url: "https://he-accounts.force.com/SmartHome/services/oauth2/authorize?response_type=token+id_token&client_id=3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6&redirect_uri=hon%3A%2F%2Fmobilesdk%2Fdetect%2Foauth%2Fdone&display=touch&scope=api%20openid%20refresh_token%20web&nonce=0813546c-8bee-4c18-b626-63588a3174a5",
            headers: {
                Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "de-de",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
            },
            maxRedirects: 0,
        })
            .then((res) => {
                this.log.error("Login step #1 failed");
                this.log.debug(JSON.stringify(res.data));
                return "";
            })
            .catch((error) => {
                if (error.response && error.response.status === 302) {
                    return error.response.headers.location;
                }
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
        if (!initUrl) {
            return;
        }
        const fwuid = await this.requestClient({
            method: "get",
            url: "https://he-accounts.force.com/SmartHome/s/login/?System=IoT_Mobile_App&RegistrationSubChannel=hOn",
            headers: {
                Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "de-de",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
            },
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                let fwuid = res.headers.link;
                fwuid = decodeURIComponent(fwuid);
                const idsJSON = JSON.parse(fwuid.split("</SmartHome/s/sfsites/l/")[1].split("/app")[0]);
                idsJSON.fwuid = fwuid.split("auraFW/javascript/")[1].split("/")[0];
                return idsJSON;
            })
            .catch((error) => {
                this.log.error("Login step #2 failed");
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
        this.log.debug(`fwuid: ${JSON.stringify(fwuid)}`);
        const initSession = qs.parse(initUrl.split("?")[1]);

        const step01Url = await this.requestClient({
            method: "post",
            url: "https://he-accounts.force.com/SmartHome/s/sfsites/aura?r=3&other.LightningLoginCustom.login=1",
            headers: {
                Accept: "*/*",
                "Accept-Language": "de-de",
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            },
            data:
                "message=%7B%22actions%22%3A%5B%7B%22id%22%3A%2277%3Ba%22%2C%22descriptor%22%3A%22apex%3A%2F%2FLightningLoginCustomController%2FACTION%24login%22%2C%22callingDescriptor%22%3A%22markup%3A%2F%2Fc%3AloginForm%22%2C%22params%22%3A%7B%22username%22%3A%22" +
                this.config.username +
                "%22%2C%22password%22%3A%22" +
                this.config.password +
                "%22%2C%22startUrl%22%3A%22%2FSmartHome%2Fsetup%2Fsecur%2FRemoteAccessAuthorizationPage.apexp%3Fsource%3D" +
                initSession.source +
                "%26display%3Dtouch%22%7D%7D%5D%7D&aura.context=" +
                JSON.stringify(fwuid) +
                "&aura.pageURI=%2FSmartHome%2Fs%2Flogin%2F%3Flanguage%3Dde%26startURL%3D%252FSmartHome%252Fsetup%252Fsecur%252FRemoteAccessAuthorizationPage.apexp%253Fsource%253D" +
                initSession.source +
                "%2526display%253Dtouch%26RegistrationSubChannel%3DhOn%26display%3Dtouch%26inst%3D68%26ec%3D302%26System%3DIoT_Mobile_App&aura.token=null",
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                if (res.data.events && res.data.events[0] && res.data.events[0].attributes && res.data.events[0].attributes) {
                    return res.data.events[0].attributes.values.url;
                }
                this.log.error("Missing step1 url");
                this.log.error(JSON.stringify(res.data));
            })
            .catch((error) => {
                this.log.error("Login step #3 failed");
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
        if (!step01Url) {
            return;
        }
        const step02Url = await this.requestClient({
            method: "get",
            url: step01Url,
            headers: {
                Accept: "*/*",
                "Accept-Language": "de-de",
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            },
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                if (res.data.includes('window.location.replace("')) {
                    return res.data.split('window.location.replace("')[1].split('")')[0];
                }
                this.log.error("Missing step2 url");
                this.log.error(JSON.stringify(res.data));
            })
            .catch((error) => {
                this.log.error("Login step #4 failed");
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
        if (!step02Url) {
            return;
        }

        const step03Url = await this.requestClient({
            method: "get",
            url: step02Url,
            headers: {
                Accept: "*/*",
                "Accept-Language": "de-de",
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            },
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                if (res.data.includes("window.location.replace('")) {
                    return res.data.split("window.location.replace('")[1].split("')")[0];
                }
                this.log.error("Login failed please logout and login in your hON and accept new terms");
                this.log.error(JSON.stringify(res.data));
            })
            .catch((error) => {
                this.log.error("Login step #5 failed");
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
        if (!step03Url) {
            return;
        }

        const step04Url = await this.requestClient({
            method: "get",
            url: "https://he-accounts.force.com" + step03Url,
            headers: {
                Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                "Accept-Language": "de-de",
            },
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                if (!res.data.includes("oauth_error_code") && res.data.includes("window.location.replace(")) {
                    return res.data.split("window.location.replace('")[1].split("')")[0];
                }
                this.log.error("Missing step4 url");
                this.log.error(JSON.stringify(res.data));
            })
            .catch((error) => {
                this.log.error("Login step #6 failed");
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
        if (!step04Url) {
            return;
        }

        this.session = qs.parse(step04Url.split("#")[1]);

        const awsLogin = await this.requestClient({
            method: "post",
            url: "https://api-iot.he.services/auth/v1/login",
            headers: {
                accept: "application/json, text/plain, */*",
                "content-type": "application/json;charset=utf-8",
                "user-agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
                "id-token": this.session.id_token,
                "accept-language": "de-de",
            },
            data: '{"appVersion":"1.40.2","mobileId":"245D4D83-98DE-4073-AEE8-1DB085DC0159","osVersion":"14.8","os":"ios","deviceModel":"iPhone10,5"}',
        })
            .then((res) => {
                this.log.debug("Receiving aws infos");
                this.log.debug(JSON.stringify(res.data));
                if (res.data.cognitoUser) {
                    return res.data;
                }
                this.log.error(JSON.stringify(res.data));
            })
            .catch((error) => {
                this.log.error("Login step #7 failed");
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
        if (!awsLogin) {
            return;
        }
        this.session = { ...this.session, ...awsLogin.cognitoUser };
        this.session.tokenSigned = awsLogin.tokenSigned;
        const awsPayload = JSON.stringify({
            IdentityId: "eu-west-1:cd22af9b-5fc2-4593-90e8-e00cd19d474b",
            Logins: {
                "cognito-identity.amazonaws.com": awsLogin.cognitoUser.Token,
            },
        });

        await this.requestClient({
            method: "post",
            url: "https://cognito-identity.eu-west-1.amazonaws.com/",
            headers: {
                accept: "*/*",
                "content-type": "application/x-amz-json-1.1",
                "x-amz-target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
                "user-agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
                "x-amz-content-sha256": crypto.createHash("sha256").update(awsPayload).digest("hex"),
                "x-amz-user-agent": "aws-amplify/1.2.3 react-native aws-amplify/1.2.3 react-native callback",
                "accept-language": "de-de",
            },
            data: awsPayload,
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.setState("info.connection", true, true);
            })
            .catch((error) => {
                this.log.error("Login step #aws failed");
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }
    async getDeviceList() {
        await this.requestClient({
            method: "get",
            url: "https://api-iot.he.services/commands/v1/appliance",
            headers: {
                accept: "application/json, text/plain, */*",
                "id-token": this.session.id_token,
                "cognito-token": this.session.Token,
                "user-agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
                "accept-language": "de-de",
            },
        })
            .then(async (res) => {
                this.log.debug(JSON.stringify(res.data));
                if (!res.data.payload.appliances) {
                    this.log.error("No devices found");
                    return;
                }
                this.log.info(`Found ${res.data.payload.appliances.length} devices`);
                for (const device of res.data.payload.appliances) {
                    const id = device.macAddress;
                    this.deviceArray.push(device);
                    let name = device.applianceTypeName;
                    if (device.modelName) {
                        name += " " + device.modelName;
                    }
                    await this.setObjectNotExistsAsync(id, {
                        type: "device",
                        common: {
                            name: name,
                        },
                        native: {},
                    });
                    await this.setObjectNotExistsAsync(id + ".remote", {
                        type: "channel",
                        common: {
                            name: "Remote Controls",
                        },
                        native: {},
                    });
                    await this.setObjectNotExistsAsync(id + ".stream", {
                        type: "channel",
                        common: {
                            name: "Data from mqtt stream",
                        },
                        native: {},
                    });
                    await this.setObjectNotExistsAsync(id + ".general", {
                        type: "channel",
                        common: {
                            name: "General Information",
                        },
                        native: {},
                    });

                    const remoteArray = [
                        { command: "refresh", name: "True = Refresh" },
                        { command: "stopProgram", name: "True = stop" },
                        {
                            command: "send",
                            name: "Send a custom command",
                            type: "json",
                            role: "json",
                            def: `{
                                "macAddress": "id of the device set by adapter",
                                "timestamp": "2022-05-10T08:16:35.010Z",
                                "commandName": "startProgram",
                                "programName": "PROGRAMS.TD.CARE_45",
                                "transactionId": "2022-05-10T08:16:35.011Z",
                                "applianceOptions": {
                                    "opt1": "anticrease",
                                    "opt2": "dryingManager",
                                    "opt3": "bestIroning",
                                    "opt4": "hybrid"
                                },
                                "device": {
                                    "mobileOs": "ios",
                                    "mobileId": "245D4D83-98DE-4073-AEE8-1DB085DC0158",
                                    "osVersion": "15.5",
                                    "appVersion": "1.40.2",
                                    "deviceModel": "iPhone10,5"
                                },
                                "attributes": {
                                    "prStr": "Care 45",
                                    "energyLabel": "0",
                                    "channel": "mobileApp",
                                    "origin": "lastProgram"
                                },
                                "ancillaryParameters": {
                                    "dryTimeMM": "45",
                                    "energyLabel": "0",
                                    "functionalId": "8",
                                    "programFamily": "[dashboard]",
                                    "programRules": {
                                        "opt3": {
                                            "dryLevel": {
                                                "2|3|4": {
                                                    "fixedValue": "0",
                                                    "typology": "fixed"
                                                }
                                            }
                                        },
                                        "dryTime": {
                                            "dryTimeMM": {
                                                "30": {
                                                    "fixedValue": "1",
                                                    "typology": "fixed"
                                                },
                                                "45": {
                                                    "fixedValue": "2",
                                                    "typology": "fixed"
                                                },
                                                "59": {
                                                    "fixedValue": "3",
                                                    "typology": "fixed"
                                                },
                                                "70": {
                                                    "fixedValue": "4",
                                                    "typology": "fixed"
                                                },
                                                "80": {
                                                    "fixedValue": "5",
                                                    "typology": "fixed"
                                                },
                                                "90": {
                                                    "fixedValue": "6",
                                                    "typology": "fixed"
                                                },
                                                "100": {
                                                    "fixedValue": "7",
                                                    "typology": "fixed"
                                                },
                                                "110": {
                                                    "fixedValue": "8",
                                                    "typology": "fixed"
                                                },
                                                "120": {
                                                    "fixedValue": "9",
                                                    "typology": "fixed"
                                                },
                                                "130": {
                                                    "fixedValue": "10",
                                                    "typology": "fixed"
                                                },
                                                "140": {
                                                    "fixedValue": "11",
                                                    "typology": "fixed"
                                                },
                                                "150": {
                                                    "fixedValue": "12",
                                                    "typology": "fixed"
                                                },
                                                "160": {
                                                    "fixedValue": "13",
                                                    "typology": "fixed"
                                                },
                                                "170": {
                                                    "fixedValue": "14",
                                                    "typology": "fixed"
                                                },
                                                "180": {
                                                    "fixedValue": "15",
                                                    "typology": "fixed"
                                                },
                                                "190": {
                                                    "fixedValue": "16",
                                                    "typology": "fixed"
                                                },
                                                "200": {
                                                    "fixedValue": "17",
                                                    "typology": "fixed"
                                                },
                                                "210": {
                                                    "fixedValue": "18",
                                                    "typology": "fixed"
                                                },
                                                "220": {
                                                    "fixedValue": "19",
                                                    "typology": "fixed"
                                                }
                                            }
                                        },
                                        "dryLevel": {
                                            "opt3": {
                                                "1": {
                                                    "fixedValue": "1",
                                                    "typology": "fixed"
                                                }
                                            }
                                        }
                                    },
                                    "remoteActionable": "1",
                                    "remoteVisible": "1",
                                    "suggestedLoadD": "2"
                                },
                                "parameters": {
                                    "dryTime": "2",
                                    "dryingManager": "0",
                                    "hybrid": "1",
                                    "checkUpStatus": "0",
                                    "anticrease": "0",
                                    "delayTime": "0",
                                    "prCode": "54",
                                    "prPosition": "13",
                                    "dryLevel": "0",
                                    "bestIroning": "0",
                                    "onOffStatus": "1"
                                },
                                "applianceType": "TD"
                            }`,
                        },
                    ];
                    remoteArray.forEach((remote) => {
                        this.setObjectNotExists(id + ".remote." + remote.command, {
                            type: "state",
                            common: {
                                name: remote.name || "",
                                type: remote.type || "boolean",
                                role: remote.role || "boolean",
                                def: remote.def || false,
                                write: true,
                                read: true,
                            },
                            native: {},
                        });
                    });
                    this.json2iob.parse(id + ".general", device);
                }
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }
    async connectMqtt() {
        this.log.info("Connecting to MQTT");

        this.device = awsIot.device({
            debug: false,
            protocol: "wss-custom-auth",
            host: "a30f6tqw0oh1x0-ats.iot.eu-west-1.amazonaws.com",
            customAuthHeaders: {
                "X-Amz-CustomAuthorizer-Name": "candy-iot-authorizer",
                "X-Amz-CustomAuthorizer-Signature": this.session.tokenSigned,
                token: this.session.id_token,
            },
        });
        this.device.on("connect", () => {
            this.log.info("mqtt connected");
            for (const device of this.deviceArray) {
                this.log.info(`subscribe to ${device.macAddress}`);
                this.device.subscribe("haier/things/" + device.macAddress + "/event/appliancestatus/update");
                this.device.subscribe("haier/things/" + device.macAddress + "/event/discovery/update");
                this.device.subscribe("$aws/events/presence/connected/" + device.macAddress);
            }
        });

        this.device.on("message", (topic, payload) => {
            this.log.debug(`message ${topic} ${payload.toString()}`);
            try {
                const message = JSON.parse(payload.toString());
                this.json2iob.parse(message.macAddress + ".stream", message, { preferedArrayName: "parName", channelName: "data from mqtt stream" });
            } catch (error) {
                this.log.error(error);
            }
        });
        this.device.on("error", () => {
            this.log.debug("error");
        });
        this.device.on("reconnect", () => {
            this.log.info("reconnect");
        });
        this.device.on("offline", () => {
            this.log.info("disconnect");
        });
    }

    async updateDevices() {
        const statusArray = [
            {
                path: "context",
                url: "https://api-iot.he.services/commands/v1/context?macAddress=$mac&applianceType=$type&category=CYCLE",
                desc: "Current context",
            },
        ];

        const headers = {
            accept: "application/json, text/plain, */*",
            "id-token": this.session.id_token,
            "cognito-token": this.session.Token,
            "user-agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
            "accept-language": "de-de",
        };
        for (const device of this.deviceArray) {
            const id = device.macAddress;
            for (const element of statusArray) {
                let url = element.url.replace("$mac", id);
                url = url.replace("$type", device.applianceTypeName);

                await this.requestClient({
                    method: "get",
                    url: url,
                    headers: headers,
                })
                    .then((res) => {
                        this.log.debug(JSON.stringify(res.data));
                        if (!res.data) {
                            return;
                        }
                        let data = res.data;
                        if (data.payload) {
                            data = data.payload;
                        }

                        const forceIndex = null;
                        const preferedArrayName = null;

                        this.json2iob.parse(id + "." + element.path, data, { forceIndex: forceIndex, preferedArrayName: preferedArrayName, channelName: element.desc });
                    })
                    .catch((error) => {
                        if (error.response) {
                            if (error.response.status === 401) {
                                error.response && this.log.debug(JSON.stringify(error.response.data));
                                this.log.info(element.path + " receive 401 error. Refresh Token in 60 seconds");
                                this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
                                this.refreshTokenTimeout = setTimeout(() => {
                                    this.refreshToken();
                                }, 1000 * 60);

                                return;
                            }
                        }
                        this.log.error(url);
                        this.log.error(error);
                        error.response && this.log.error(JSON.stringify(error.response.data));
                    });
            }
        }
    }
    async refreshToken() {
        if (!this.session) {
            this.log.error("No session found relogin");
            await this.login();
            return;
        }
        await this.requestClient({
            method: "post",
            url: "https://he-accounts.force.com/SmartHome/services/oauth2/token?client_id=3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6&refresh_token=5Aep861ikNsOLQGnboERb071AJnH78LQeRc565OSzMhK0X5_QLacxYNOwxdk90V6FGRGPK_T5a.mvc48glv7JAK&grant_type=refresh_token",
            headers: {
                Host: "he-accounts.force.com",
                Accept: "application/json",
                Cookie: "BrowserId=3elRuc8OEeytLV_-N9BjLA; CookieConsentPolicy=0:1; LSKey-c$CookieConsentPolicy=0:1; oinfo=c3RhdHVzPUFDVElWRSZ0eXBlPTYmb2lkPTAwRFUwMDAwMDAwTGtjcQ==",
                "User-Agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
                "Accept-Language": "de-de",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data: qs.stringify({
                "https://he-accounts.force.com/SmartHome/services/oauth2/token?client_id": "3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6",
                refresh_token: this.session.refresh_token,
                grant_type: "refresh_token",
            }),
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.session = { ...this.session, ...res.data };
                this.setState("info.connection", true, true);
            })
            .catch((error) => {
                this.log.error("refresh token failed");
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
                this.log.error("Start relogin in 1min");
                this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
                this.reLoginTimeout = setTimeout(() => {
                    this.login();
                }, 1000 * 60 * 1);
            });
    }

    /**
     * Is called when adapter shuts down - callback has to be called under any circumstances!
     * @param {() => void} callback
     */
    onUnload(callback) {
        try {
            this.setState("info.connection", false, true);
            this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
            this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
            this.updateInterval && clearInterval(this.updateInterval);
            this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
            callback();
        } catch (e) {
            callback();
        }
    }

    /**
     * Is called if a subscribed state changes
     * @param {string} id
     * @param {ioBroker.State | null | undefined} state
     */
    async onStateChange(id, state) {
        if (state) {
            if (!state.ack) {
                const deviceId = id.split(".")[2];
                const command = id.split(".")[4];

                let data = {};
                if (id.split(".")[3] !== "remote") {
                    return;
                }

                if (command === "refresh") {
                    this.updateDevices();

                    return;
                }
                const dt = new Date().toISOString();
                if (command === "stopProgram") {
                    data = {
                        macAddress: deviceId,
                        timestamp: dt,
                        commandName: "stopProgram",
                        transactionId: deviceId + "_" + dt,
                        applianceOptions: {},
                        device: {
                            mobileId: "245D4D83-98DE-4073-AEE8-1DB085DC0158",
                            mobileOs: "ios",
                            osVersion: "15.5",
                            appVersion: "1.40.2",
                            deviceModel: "iPhone10,5",
                        },
                        attributes: {
                            channel: "mobileApp",
                            origin: "standardProgram",
                        },
                        ancillaryParameters: {},
                        parameters: {
                            onOffStatus: "0",
                        },
                        applianceType: "",
                    };
                }
                if (command === "send") {
                    data = JSON.parse(state.val);
                }
                data.macAddress = deviceId;
                data.timestamp = dt;
                data.transactionId = deviceId + "_" + dt;
                this.log.debug(JSON.stringify(data));

                await this.requestClient({
                    method: "post",
                    url: "https://api-iot.he.services/commands/v1/send",
                    headers: {
                        accept: "application/json, text/plain, */*",
                        "id-token": this.session.id_token,
                        "cognito-token": this.session.Token,
                        "user-agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
                        "accept-language": "de-de",
                    },
                    data: data,
                })
                    .then((res) => {
                        this.log.info(JSON.stringify(res.data));
                        return res.data;
                    })
                    .catch((error) => {
                        this.log.error(error);
                        if (error.response) {
                            this.log.error(JSON.stringify(error.response.data));
                        }
                    });
            }
        }
    }
}

if (require.main !== module) {
    // Export the constructor in compact mode
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    module.exports = (options) => new Hoover(options);
} else {
    // otherwise start the instance directly
    new Hoover();
}

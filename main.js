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
const { HttpsCookieAgent } = require("http-cookie-agent");

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
                jar: this.cookieJar,
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
            await this.updateDevices();
            this.updateInterval = setInterval(async () => {
                await this.updateDevices();
            }, this.config.interval * 60 * 1000);
            this.refreshTokenInterval = setInterval(() => {
                this.refreshToken();
            }, 2 * 60 * 60 * 1000);
        }
    }
    async login() {
        const initSession = await this.requestClient({
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
                this.log.debug(JSON.stringify(res.data));
                return "";
            })
            .catch((error) => {
                if (error.response && error.response.status === 302) {
                    return qs.parse(error.response.headers.location.split("?")[1]);
                }
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
        if (!initSession) {
            return;
        }

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
                "%26display%3Dtouch%22%7D%7D%5D%7D&aura.context=%7B%22mode%22%3A%22PROD%22%2C%22fwuid%22%3A%222yRFfs4WfGnFrNGn9C_dGg%22%2C%22app%22%3A%22siteforce%3AloginApp2%22%2C%22loaded%22%3A%7B%22APPLICATION%40markup%3A%2F%2Fsiteforce%3AloginApp2%22%3A%22PnuMahsrn7JWWgS2n6sUkQ%22%7D%2C%22dn%22%3A%5B%5D%2C%22globals%22%3A%7B%7D%2C%22ct%22%3A1%2C%22uad%22%3Afalse%7D&aura.pageURI=%2FSmartHome%2Fs%2Flogin%2F%3Flanguage%3Dde%26startURL%3D%252FSmartHome%252Fsetup%252Fsecur%252FRemoteAccessAuthorizationPage.apexp%253Fsource%253D" +
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
                this.log.error("Missing step3 url");
                this.log.error(JSON.stringify(res.data));
            })
            .catch((error) => {
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
                this.log.debug(JSON.stringify(res.data));
                if (res.data.cognitoUser) {
                    return res.data;
                }
                this.log.error(JSON.stringify(res.data));
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
        if (!awsLogin) {
            return;
        }
        this.session = { ...this.session, ...awsLogin.cognitoUser };
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
                    const id = device.serialNumber;
                    this.deviceArray.push(id);
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
                    await this.setObjectNotExistsAsync(id + ".general", {
                        type: "channel",
                        common: {
                            name: "General Information",
                        },
                        native: {},
                    });

                    const remoteArray = [{ command: "Refresh", name: "True = Refresh" }];
                    remoteArray.forEach((remote) => {
                        this.setObjectNotExists(id + ".remote." + remote.command, {
                            type: "state",
                            common: {
                                name: remote.name || "",
                                type: remote.type || "boolean",
                                role: remote.role || "boolean",
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

    async updateDevices() {
        const statusArray = [
            {
                path: "general",
                url: "https://api-iot.he.services/commands/v1/appliance",
                desc: "General",
            },
        ];

        const headers = {
            accept: "application/json, text/plain, */*",
            "id-token": this.session.id_token,
            "cognito-token": this.session.Token,
            "user-agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
            "accept-language": "de-de",
        };
        for (const id of this.deviceArray) {
            for (const element of statusArray) {
                const url = element.url.replace("$vin", id);

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
                        const data = res.data;

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
            this.refreshTimeout && clearTimeout(this.refreshTimeout);
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
                if (id.split(".")[3] !== "remote") {
                    return;
                }

                if (command === "Refresh") {
                    this.updateDevices();
                }
                const data = {};
                this.log.debug(JSON.stringify(data));

                await this.requestClient({
                    method: "post",
                    url: "",
                    headers: {
                        accept: "*/*",
                        "content-type": "application/json",
                        "accept-language": "de",
                        authorization: "Bearer " + this.session.access_token,
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
                this.refreshTimeout && clearTimeout(this.refreshTimeout);
                this.refreshTimeout = setTimeout(async () => {
                    await this.updateDevices();
                }, 10 * 1000);
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

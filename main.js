"use strict";

/*
 * Created with @iobroker/create-adapter v1.34.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const axios = require("axios").default;
const Json2iob = require("json2iob");
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
    this.userAgent = "ioBroker v0.0.7";

    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.session = {};
    this.subscribeStates("*");
    this.log.info("starting login");
    if (this.config.type !== "wizard") {
      this.config.interval = 10;
    }
    await this.login();

    if (this.session.access_token) {
      this.setState("info.connection", true, true);
      await this.getDeviceList();
      if (this.config.type !== "wizard") {
        await this.connectMqtt();
        await this.updateDevices();
      }
      this.updateInterval = setInterval(async () => {
        if (this.config.type === "wizard") {
          await this.getDeviceList();
        } else {
          await this.updateDevices();
        }
      }, this.config.interval * 60 * 1000);
      this.refreshTokenInterval = setInterval(() => {
        this.refreshToken();
      }, 2 * 60 * 60 * 1000);
    }
  }

  extractInputsAndFormUrl(html) {
    const hiddenInputs = {};
    let formUrl = html.split("<form")[1].split('action="')[1].split('"')[0];
    formUrl = formUrl.replace(/&amp;/g, "&");
    const inputs = html.split("<input");
    for (const input of inputs) {
      // if (input.includes('type="hidden"')) {
      let name = input.split('id="')[1].split('"')[0];
      if (input.includes('name="')) {
        name = input.split('name="')[1].split('"')[0];
      }
      let value = "";
      if (input.includes('value="')) {
        value = input.split('value="')[1].split('"')[0];
      }
      hiddenInputs[name] = value;
      // }
    }
    return { formUrl, hiddenInputs };
  }
  async login() {
    let loginUrl =
      "https://account2.hon-smarthome.com/services/oauth2/authorize/expid_Login?response_type=token+id_token&client_id=3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6&redirect_uri=hon%3A%2F%2Fmobilesdk%2Fdetect%2Foauth%2Fdone&display=touch&scope=api%20openid%20refresh_token%20web&nonce=b8f38cb9-26f0-4aed-95b4-aa504f5e1971";
    if (this.config.type === "wizard") {
      loginUrl =
        "https://haiereurope.my.site.com/HooverApp/services/oauth2/authorize?client_id=3MVG9QDx8IX8nP5T2Ha8ofvlmjKuido4mcuSVCv4GwStG0Lf84ccYQylvDYy9d_ZLtnyAPzJt4khJoNYn_QVB&redirect_uri=hoover://mobilesdk/detect/oauth/done&display=touch&device_id=245D4D83-98DE-4073-AEE8-1DB085DC0159&response_type=token&scope=api%20id%20refresh_token%20web%20openid";
    }

    const initUrl = await this.requestClient({
      method: "get",
      url: loginUrl,
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
    const initSession = qs.parse(initUrl.split("?")[1]);
    let fwurl = "https://he-accounts.force.com/SmartHome/s/login/?System=IoT_Mobile_App&RegistrationSubChannel=hOn";
    fwurl =
      "https://account2.hon-smarthome.com/NewhOnLogin?display=touch%2F&ec=302&startURL=%2F%2Fsetup%2Fsecur%2FRemoteAccessAuthorizationPage.apexp%3Fsource%3D" +
      initSession.source;
    if (this.config.type === "wizard") {
      fwurl =
        "https://haiereurope.my.site.com/HooverApp/login?display=touch&ec=302&inst=68&startURL=%2FHooverApp%2Fsetup%2Fsecur%2FRemoteAccessAuthorizationPage.apexp%3Fsource%3D" +
        initSession.source +
        "%26display%3Dtouch";
    }
    const { formUrl, hiddenInputs } = await this.requestClient({
      method: "get",
      url: fwurl,
      headers: {
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "de-de",
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
      },
    })
      .then((res) => {
        this.log.debug(res.data);
        return this.extractInputsAndFormUrl(res.data);
      })
      .catch((error) => {
        this.log.error("Login step #2 failed");
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });

    if (this.config.type === "wizard") {
      await this.requestClient({
        method: "post",
        url: "https://haiereurope.my.site.com/HooverApp/login",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Connection: "keep-alive",
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
          "Accept-Language": "de-de",
        },
        data: qs.stringify({
          pqs:
            "?startURL=%2FHooverApp%2Fsetup%2Fsecur%2FRemoteAccessAuthorizationPage.apexp%3Fsource%3" +
            initSession.source +
            "%26display%3Dtouch&ec=302&display=touch&inst=68",
          un: this.config.username,
          width: "414",
          height: "736",
          hasRememberUn: "true",
          startURL: "/HooverApp/setup/secur/RemoteAccessAuthorizationPage.apexp?source=" + initSession.source + "&display=touch",
          loginURL: "",
          loginType: "",
          useSecure: "true",
          local: "",
          lt: "standard",
          qs: "",
          locale: "de",
          oauth_token: "",
          oauth_callback: "",
          login: "",
          serverid: "",
          display: "touch",
          username: this.config.username,
          pw: this.config.password,
          rememberUn: "on",
        }),
      })
        .then(async (res) => {
          this.log.debug(JSON.stringify(res.data));
          if (this.config.type === "wizard") {
            const forwardUrl = res.data.split('<a href="')[1].split('">')[0];
            const forward2Url = await this.requestClient({ method: "get", url: forwardUrl }).then((res) => {
              this.log.debug(JSON.stringify(res.data));
              return res.data.split("window.location.href ='")[1].split("';")[0];
            });
            const forward3Url = await this.requestClient({ method: "get", url: "https://haiereurope.my.site.com" + forward2Url }).then(
              (res) => {
                this.log.debug(JSON.stringify(res.data));
                return res.data.split("window.location.href ='")[1].split(";")[0];
              },
            );
            this.log.debug(JSON.stringify(forward3Url));
            this.session = qs.parse(forward3Url.split("#")[1]);
            await this.refreshToken();
          } else {
            if (res.data.events && res.data.events[0] && res.data.events[0].attributes && res.data.events[0].attributes) {
              return res.data.events[0].attributes.values.url;
            }
            this.log.error("Missing step1 url");
            this.log.error(JSON.stringify(res.data));
          }
        })
        .catch((error) => {
          this.log.error("Login step #3 failed");
          this.log.error(error);
          error.response && this.log.error(JSON.stringify(error.response.data));
        });
      return;
    }
    hiddenInputs["j_id0:loginForm:username"] = this.config.username;
    hiddenInputs["j_id0:loginForm:password"] = this.config.password;
    const step02Url = await this.requestClient({
      method: "post",
      url: formUrl,
      headers: {
        Accept: "*/*",
        "Accept-Language": "de-de",
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
      },
      data: hiddenInputs,
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data.includes("window.location.replace('")) {
          return res.data.split("window.location.replace('")[1].split("')")[0];
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
        if (res.data.includes(`window.location.replace("`)) {
          return res.data.split(`window.location.replace("`)[1].split(`")`)[0];
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
    const step03bUrl = await this.requestClient({
      method: "get",
      url: step03Url,
      headers: {
        Accept: "*/*",
        "Accept-Language": "de-de",
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
      },
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data.includes(`window.location.replace('`)) {
          return res.data.split(`window.location.replace('`)[1].split(`')`)[0];
        }
        this.log.error("Login failed please logout and login in your hON and accept new terms");
        this.log.error(JSON.stringify(res.data));
      })
      .catch((error) => {
        this.log.error("Login step #5 failed");
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
    if (!step03bUrl) {
      return;
    }
    const step04Url = await this.requestClient({
      method: "get",
      url: "https://account2.hon-smarthome.com" + step03bUrl,
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
        "user-agent": "hOn/1 CFNetwork/1240.0.4 Darwin/20.6.0",
        "id-token": this.session.id_token,
        "accept-language": "de-de",
      },
      data: {
        appVersion: "2.0.9",
        firebaseToken:
          "cvufm5cb9rI:APA91bG9jRyOd35YuAhnx-B0OW9WZ27QRJZUeYKGSfCQv9eDHr7rBHTCMt0pzY2R3HELIG844tDZ-Ip3dMA1_3jRBgYdPYt9byKcYd6XAi6jqJhiIimfQlAFeb5ZZvDmeqib_2UWl3yY",
        mobileId: "245D4D83-98DE-4073-AEE8-1DB085DC0158",
        osVersion: "14.8",
        os: "ios",
        deviceModel: "iPhone10,5",
      },
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
      IdentityId: awsLogin.cognitoUser.IdentityId,
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
        this.log.info("Login successful");
        this.setState("info.connection", true, true);
      })
      .catch((error) => {
        this.log.error("Login step #aws failed");
        this.log.error(JSON.stringify(awsLogin));
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }
  async getDeviceList() {
    let deviceListUrl = "https://api-iot.he.services/commands/v1/appliance";
    if (this.config.type === "wizard") {
      deviceListUrl = "https://simply-fi.herokuapp.com/api/v1/appliances.json?with_hidden_programs=1";
    }
    await this.requestClient({
      method: "get",
      url: deviceListUrl,
      headers: {
        accept: "application/json, text/plain, */*",
        "id-token": this.session.id_token,
        "cognito-token": this.session.Token,
        "user-agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
        "accept-language": "de-de",
        Authorization: "Bearer " + this.session.id_token,
        "Salesforce-Auth": 1,
      },
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));

        let appliances;
        if (this.config.type === "wizard") {
          appliances = res.data;
        } else {
          appliances = res.data.payload.appliances;
        }
        if (!appliances) {
          this.log.error("No devices found");
          return;
        }
        this.log.info(`Found ${appliances.length} devices`);
        for (let device of appliances) {
          if (device.appliance) {
            device = device.appliance;
          }
          let id = device.macAddress || device.serialNumber;
          if (this.config.type === "wizard") {
            id = device.id;
          }
          this.deviceArray.push(device);
          let name = device.applianceTypeName || device.appliance_model;
          if (device.modelName) {
            name += " " + device.modelName;
          }
          if (device.nickName) {
            name += " " + device.nickName;
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
          if (!this.config.type === "wizard") {
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
          }
          const remoteArray = [
            { command: "refresh", name: "True = Refresh" },
            { command: "stopProgram", name: "True = stop" },
          ];
          if (this.config.type === "wizard") {
            remoteArray.push({
              command: "send",
              name: "Send a custom command",
              type: "string",
              role: "text",
              def: `StartStop=1&Program=P2&DelayStart=0&TreinUno=1&Eco=1&MetaCarico=0&ExtraDry=0&OpzProg=0`,
            });
          } else {
            remoteArray.push({
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
            });
          }

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
          if (this.config.type === "wizard") {
            this.json2iob.parse(id, device);
          } else {
            this.json2iob.parse(id + ".general", device);
          }
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
        const id = device.macAddress || device.serialNumber;
        this.log.info(`subscribe to ${id}`);
        this.device.subscribe("haier/things/" + id + "/event/appliancestatus/update");
        this.device.subscribe("haier/things/" + id + "/event/discovery/update");
        this.device.subscribe("$aws/events/presence/connected/" + id);
      }
    });

    this.device.on("message", (topic, payload) => {
      this.log.debug(`message ${topic} ${payload.toString()}`);
      try {
        const message = JSON.parse(payload.toString());
        const id = message.macAddress || message.serialNumber;
        this.json2iob.parse(id + ".stream", message, {
          preferedArrayName: "parName",
          channelName: "data from mqtt stream",
        });
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
      const id = device.macAddress || device.serialNumber;
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

            this.json2iob.parse(id + "." + element.path, data, {
              forceIndex: forceIndex,
              preferedArrayName: preferedArrayName,
              channelName: element.desc,
            });
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
    if (this.config.type === "wizard") {
      await this.requestClient({
        method: "post",
        maxBodyLength: Infinity,
        url: "https://haiereurope.my.site.com/HooverApp/services/oauth2/token",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Connection: "keep-alive",
          Accept: "*/*",
          "User-Agent": "hoover-ios/762 CFNetwork/1240.0.4 Darwin/20.6.0",
          "Accept-Language": "de-de",
        },
        data: qs.stringify({
          format: "json",
          redirect_uri: "hoover://mobilesdk/detect/oauth/done",
          client_id: "3MVG9QDx8IX8nP5T2Ha8ofvlmjKuido4mcuSVCv4GwStG0Lf84ccYQylvDYy9d_ZLtnyAPzJt4khJoNYn_QVB",
          device_id: "245D4D83-98DE-4073-AEE8-1DB085DC0158",
          grant_type: "refresh_token",
          refresh_token: this.session.refresh_token,
        }),
      }).then((res) => {
        this.log.debug(JSON.stringify(res.data));
        this.session = { ...this.session, ...res.data };
      });
      return;
    }
    await this.requestClient({
      method: "post",
      url:
        "https://account2.hon-smarthome.com/services/oauth2/token?client_id=3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6&refresh_token=" +
        this.session.refresh_token +
        "&grant_type=refresh_token",
      headers: {
        Accept: "application/json",
        Cookie:
          "BrowserId=3elRuc8OEeytLV_-N9BjLA; CookieConsentPolicy=0:1; LSKey-c$CookieConsentPolicy=0:1; oinfo=c3RhdHVzPUFDVElWRSZ0eXBlPTYmb2lkPTAwRFUwMDAwMDAwTGtjcQ==",
        "User-Agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
        "Accept-Language": "de-de",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      data: qs.stringify({
        "https://account2.hon-smarthome.com/services/oauth2/token?client_id":
          "3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6",
        refresh_token: this.session.refresh_token,
        grant_type: "refresh_token",
      }),
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        this.session = { ...this.session, ...res.data };
        this.device.updateCustomAuthHeaders({
          "X-Amz-CustomAuthorizer-Name": "candy-iot-authorizer",
          "X-Amz-CustomAuthorizer-Signature": this.session.tokenSigned,
          token: this.session.id_token,
        });
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
      this.log.error(e);
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
          data = "Reset=1";
          if (this.config.type !== "wizard") {
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
        }
        if (command === "send") {
          if (this.config.type === "wizard") {
            data = state.val;
          } else {
            data = JSON.parse(state.val);
          }
        }
        if (this.config.type == "wizard") {
          data = {
            appliance_id: deviceId,
            body: data,
          };
        } else {
          data.macAddress = deviceId;
          data.timestamp = dt;
          data.transactionId = deviceId + "_" + dt;
        }
        this.log.debug(JSON.stringify(data));
        let url = "https://api-iot.he.services/commands/v1/send";
        if (this.config.type === "wizard") {
          url = "https://simply-fi.herokuapp.com/api/v1/commands.json";
        }
        await this.requestClient({
          method: "post",
          url: url,
          headers: {
            accept: "application/json, text/plain, */*",
            "id-token": this.session.id_token,
            "cognito-token": this.session.Token,
            "user-agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
            "accept-language": "de-de",
            Authorization: "Bearer " + this.session.id_token,
            "Salesforce-Auth": 1,
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

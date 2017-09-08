"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _bluebird = require("bluebird");

var _bluebird2 = _interopRequireDefault(_bluebird);

var _extends2 = require("babel-runtime/helpers/extends");

var _extends3 = _interopRequireDefault(_extends2);

exports.sign = sign;
exports.verify = verify;

var _jsonwebtoken = require("jsonwebtoken");

var _jsonwebtoken2 = _interopRequireDefault(_jsonwebtoken);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const mergeOptions = options => (0, _extends3.default)({}, options || {}, { algorithm: "HS256" });
function sign(token, signatureKey, options) {
    return new _bluebird2.default((resolve, reject) => {
        _jsonwebtoken2.default.sign(token, signatureKey, mergeOptions(options), (error, encodedToken) => {
            if (!error) {
                resolve(encodedToken);
                return;
            }
            reject(error);
        });
    });
}

function verify(encodedToken, signatureKey, options) {
    return new _bluebird2.default((resolve, reject) => {
        _jsonwebtoken2.default.verify(encodedToken, signatureKey, mergeOptions(options), (error, token) => {
            if (!error) {
                resolve(token);
                return;
            }
            reject(error);
        });
    });
}
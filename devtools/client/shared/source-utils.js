/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
"use strict";

const { URL } = require("sdk/url");
const { L10N } = require("resource://devtools/client/shared/widgets/ViewHelpers.jsm").ViewHelpers;
const l10n = new L10N("chrome://devtools/locale/components.properties");
const UNKNOWN_SOURCE_STRING = l10n.getStr("frame.unknownSource");

// Character codes used in various parsing helper functions.
const CHAR_CODE_A = "a".charCodeAt(0);
const CHAR_CODE_C = "c".charCodeAt(0);
const CHAR_CODE_D = "d".charCodeAt(0);
const CHAR_CODE_E = "e".charCodeAt(0);
const CHAR_CODE_F = "f".charCodeAt(0);
const CHAR_CODE_H = "h".charCodeAt(0);
const CHAR_CODE_I = "i".charCodeAt(0);
const CHAR_CODE_J = "j".charCodeAt(0);
const CHAR_CODE_L = "l".charCodeAt(0);
const CHAR_CODE_M = "m".charCodeAt(0);
const CHAR_CODE_O = "o".charCodeAt(0);
const CHAR_CODE_P = "p".charCodeAt(0);
const CHAR_CODE_R = "r".charCodeAt(0);
const CHAR_CODE_S = "s".charCodeAt(0);
const CHAR_CODE_T = "t".charCodeAt(0);
const CHAR_CODE_U = "u".charCodeAt(0);
const CHAR_CODE_COLON = ":".charCodeAt(0);
const CHAR_CODE_SLASH = "/".charCodeAt(0);
const CHAR_CODE_CAP_S = "S".charCodeAt(0);

// The cache used in the `nsIURL` function.
const gURLStore = new Map();
// The cache used in the `getSourceNames` function.
const gSourceNamesStore = new Map();

/**
 * Takes a string and returns an object containing all the properties
 * available on an URL instance, with additional properties (fileName),
 * Leverages caching.
 *
 * @TODO If loaded through Browser Loader, we can use the web API URL
 * directly, giving us the same interface without needing the SDK --
 * we still need to add `fileName` though.
 *
 * @param {String} location
 * @return {Object?} An object containing most properties available
 *                   in https://developer.mozilla.org/en-US/docs/Web/API/URL
 */

function parseURL(location) {
  let url = gURLStore.get(location);

  if (url !== void 0) {
    return url;
  }

  try {
    url = new URL(location);
    // Definitions:
    // Example: https://foo.com:8888/file.js
    // `hostname`: "foo.com"
    // `host`: "foo.com:8888"
    //
    // sdk/url does not match several definitions.: both `host` and `hostname`
    // are actually the `hostname` (even though this is the `host` property on the
    // original nsIURL, with `hostPort` representing the actual `host` name, AH!!!)
    // So normalize all that garbage here.
    let isChrome = isChromeScheme(location);
    let fileName = url.fileName || "/";
    let hostname = isChrome ? null : url.hostname;
    let host = isChrome ? null :
               url.port ? `${url.host}:${url.port}` :
               url.host;

    let parsed = Object.assign({}, url, { host, fileName, hostname });
    gURLStore.set(location, parsed);
    return parsed;
  }
  catch (e) {
    gURLStore.set(location, null);
    return null;
  }
}

/**
 * Parse a source into a short and long name as well as a host name.
 *
 * @param {String} source
 *        The source to parse. Can be a URI or names like "(eval)" or "self-hosted".
 * @return {Object}
 *         An object with the following properties:
 *           - {String} short: A short name for the source.
 *             - "http://page.com/test.js#go?q=query" -> "test.js"
 *           - {String} long: The full, long name for the source, with hash/query stripped.
 *             - "http://page.com/test.js#go?q=query" -> "http://page.com/test.js"
 *           - {String?} host: If available, the host name for the source.
 *             - "http://page.com/test.js#go?q=query" -> "page.com"
 */
function getSourceNames (source) {
  let data = gSourceNamesStore.get(source);

  if (data) {
    return data;
  }

  let short, long, host;
  const sourceStr = source ? String(source) : "";

  // If `data:...` uri
  if (isDataScheme(sourceStr)) {
    let commaIndex = sourceStr.indexOf(",");
    if (commaIndex > -1) {
      // The `short` name for a data URI becomes `data:` followed by the actual
      // encoded content, omitting the MIME type, and charset.
      let short = `data:${sourceStr.substring(commaIndex + 1)}`.slice(0, 100);
      let result = { short, long: sourceStr };
      gSourceNamesStore.set(source, result);
      return result;
    }
  }

  // If Scratchpad URI, like "Scratchpad/1"; no modifications,
  // and short/long are the same.
  if (isScratchpadScheme(sourceStr)) {
    let result = { short: sourceStr, long: sourceStr };
    gSourceNamesStore.set(source, result);
    return result;
  }

  const parsedUrl = parseURL(sourceStr);

  if (!parsedUrl) {
    // Malformed URI.
    long = sourceStr;
    short = sourceStr.slice(0, 100);
  } else {
    host = parsedUrl.host;

    long = parsedUrl.href;
    if (parsedUrl.hash) {
      long = long.replace(parsedUrl.hash, "");
    }
    if (parsedUrl.search) {
      long = long.replace(parsedUrl.search, "");
    }

    short = parsedUrl.fileName;
    // If `short` is just a slash, and we actually have a path,
    // strip the slash and parse again to get a more useful short name.
    // e.g. "http://foo.com/bar/" -> "bar", rather than "/"
    if (short === "/" && parsedUrl.pathname !== "/") {
      short = parseURL(long.replace(/\/$/, "")).fileName;
    }
  }

  if (!short) {
    if (!long) {
      long = UNKNOWN_SOURCE_STRING;
    }
    short = long.slice(0, 100);
  }

  let result = { short, long, host };
  gSourceNamesStore.set(source, result);
  return result;
}

// For the functions below, we assume that we will never access the location
// argument out of bounds, which is indeed the vast majority of cases.
//
// They are written this way because they are hot. Each frame is checked for
// being content or chrome when processing the profile.

function isColonSlashSlash(location, i=0) {
  return location.charCodeAt(++i) === CHAR_CODE_COLON &&
         location.charCodeAt(++i) === CHAR_CODE_SLASH &&
         location.charCodeAt(++i) === CHAR_CODE_SLASH;
}

/**
 * Checks for a Scratchpad URI, like "Scratchpad/1"
 */
function isScratchpadScheme(location, i=0) {
  return location.charCodeAt(i)   === CHAR_CODE_CAP_S &&
         location.charCodeAt(++i) === CHAR_CODE_C &&
         location.charCodeAt(++i) === CHAR_CODE_R &&
         location.charCodeAt(++i) === CHAR_CODE_A &&
         location.charCodeAt(++i) === CHAR_CODE_T &&
         location.charCodeAt(++i) === CHAR_CODE_H &&
         location.charCodeAt(++i) === CHAR_CODE_P &&
         location.charCodeAt(++i) === CHAR_CODE_A &&
         location.charCodeAt(++i) === CHAR_CODE_D &&
         location.charCodeAt(++i) === CHAR_CODE_SLASH;
}

function isDataScheme(location, i=0) {
  return location.charCodeAt(i)   === CHAR_CODE_D &&
         location.charCodeAt(++i) === CHAR_CODE_A &&
         location.charCodeAt(++i) === CHAR_CODE_T &&
         location.charCodeAt(++i) === CHAR_CODE_A &&
         location.charCodeAt(++i) === CHAR_CODE_COLON;
}

function isContentScheme(location, i=0) {
  let firstChar = location.charCodeAt(i);

  switch (firstChar) {
  case CHAR_CODE_H: // "http://" or "https://"
    if (location.charCodeAt(++i) === CHAR_CODE_T &&
        location.charCodeAt(++i) === CHAR_CODE_T &&
        location.charCodeAt(++i) === CHAR_CODE_P) {
      if (location.charCodeAt(i + 1) === CHAR_CODE_S) {
        ++i;
      }
      return isColonSlashSlash(location, i);
    }
    return false;

  case CHAR_CODE_F: // "file://"
    if (location.charCodeAt(++i) === CHAR_CODE_I &&
        location.charCodeAt(++i) === CHAR_CODE_L &&
        location.charCodeAt(++i) === CHAR_CODE_E) {
      return isColonSlashSlash(location, i);
    }
    return false;

  case CHAR_CODE_A: // "app://"
    if (location.charCodeAt(++i) == CHAR_CODE_P &&
        location.charCodeAt(++i) == CHAR_CODE_P) {
      return isColonSlashSlash(location, i);
    }
    return false;

  default:
    return false;
  }
}

function isChromeScheme(location, i=0) {
  let firstChar = location.charCodeAt(i);

  switch (firstChar) {
  case CHAR_CODE_C: // "chrome://"
    if (location.charCodeAt(++i) === CHAR_CODE_H &&
        location.charCodeAt(++i) === CHAR_CODE_R &&
        location.charCodeAt(++i) === CHAR_CODE_O &&
        location.charCodeAt(++i) === CHAR_CODE_M &&
        location.charCodeAt(++i) === CHAR_CODE_E) {
      return isColonSlashSlash(location, i);
    }
    return false;

  case CHAR_CODE_R: // "resource://"
    if (location.charCodeAt(++i) === CHAR_CODE_E &&
        location.charCodeAt(++i) === CHAR_CODE_S &&
        location.charCodeAt(++i) === CHAR_CODE_O &&
        location.charCodeAt(++i) === CHAR_CODE_U &&
        location.charCodeAt(++i) === CHAR_CODE_R &&
        location.charCodeAt(++i) === CHAR_CODE_C &&
        location.charCodeAt(++i) === CHAR_CODE_E) {
      return isColonSlashSlash(location, i);
    }
    return false;

  case CHAR_CODE_J: // "jar:file://"
    if (location.charCodeAt(++i) === CHAR_CODE_A &&
        location.charCodeAt(++i) === CHAR_CODE_R &&
        location.charCodeAt(++i) === CHAR_CODE_COLON &&
        location.charCodeAt(++i) === CHAR_CODE_F &&
        location.charCodeAt(++i) === CHAR_CODE_I &&
        location.charCodeAt(++i) === CHAR_CODE_L &&
        location.charCodeAt(++i) === CHAR_CODE_E) {
      return isColonSlashSlash(location, i);
    }
    return false;

  default:
    return false;
  }
}

exports.parseURL = parseURL;
exports.getSourceNames = getSourceNames;
exports.isScratchpadScheme = isScratchpadScheme;
exports.isChromeScheme = isChromeScheme;
exports.isContentScheme = isContentScheme;
exports.isDataScheme = isDataScheme;

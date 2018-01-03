
// Helpers    /////////////////////////////////////////////

// Taken from https://github.com/google/closure-library/blob/e877b1eac410c0d842bcda118689759512e0e26f/closure/goog/crypt/crypt.js
// Apache Licensed
stringToUtf8ByteArray = function(str) {
  // TODO(user): Use native implementations if/when available
  var out = [], p = 0;
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    if (c < 128) {
      out[p++] = c;
    } else if (c < 2048) {
      out[p++] = (c >> 6) | 192;
      out[p++] = (c & 63) | 128;
    } else if (
        ((c & 0xFC00) == 0xD800) && (i + 1) < str.length &&
        ((str.charCodeAt(i + 1) & 0xFC00) == 0xDC00)) {
      // Surrogate Pair
      c = 0x10000 + ((c & 0x03FF) << 10) + (str.charCodeAt(++i) & 0x03FF);
      out[p++] = (c >> 18) | 240;
      out[p++] = ((c >> 12) & 63) | 128;
      out[p++] = ((c >> 6) & 63) | 128;
      out[p++] = (c & 63) | 128;
    } else {
      out[p++] = (c >> 12) | 224;
      out[p++] = ((c >> 6) & 63) | 128;
      out[p++] = (c & 63) | 128;
    }
  }
  return new Uint8Array(out);
};

// Taken from https://github.com/google/closure-library/blob/e877b1eac410c0d842bcda118689759512e0e26f/closure/goog/crypt/crypt.js
// Apache Licensed
utf8ByteArrayToString = function(bytes) {
  // TODO(user): Use native implementations if/when available
  let out = [], pos = 0, c = 0;
  while (pos < bytes.length) {
    let c1 = bytes[pos++];
    if (c1 < 128) {
      out[c++] = String.fromCharCode(c1);
    } else if (c1 > 191 && c1 < 224) {
      let c2 = bytes[pos++];
      out[c++] = String.fromCharCode((c1 & 31) << 6 | c2 & 63);
    } else if (c1 > 239 && c1 < 365) {
      // Surrogate Pair
      let c2 = bytes[pos++];
      let c3 = bytes[pos++];
      let c4 = bytes[pos++];
      let u = ((c1 & 7) << 18 | (c2 & 63) << 12 | (c3 & 63) << 6 | c4 & 63) -
          0x10000;
      out[c++] = String.fromCharCode(0xD800 + (u >> 10));
      out[c++] = String.fromCharCode(0xDC00 + (u & 1023));
    } else {
      let c2 = bytes[pos++];
      let c3 = bytes[pos++];
      out[c++] =
          String.fromCharCode((c1 & 15) << 12 | (c2 & 63) << 6 | c3 & 63);
    }
  }
  return out.join('');
};

function byteArrayToHexString(byteArray) {
	if (!byteArray) {
		return '';
	}
  
	var hexStr = '';
	for (var i = 0; i < byteArray.length; i++) {
		var hex = (byteArray[i] & 0xff).toString(16);
		hex = (hex.length === 1) ? '0' + hex : hex;
		hexStr += hex;
	}
	return hexStr.toUpperCase();
}

function hexStringToByteArray(hexString) {
  let result = new Uint8Array(hexString.length/2), i = 0;
  while (hexString.length >= 2) {
    result[i++] = parseInt(hexString.substring(0, 2), 16);
    hexString = hexString.substring(2, hexString.length);
  }
  return result;
}

//            /////////////////////////////////////////////

// KeyStorage /////////////////////////////////////////////
// Uses IndexedDB

var _db_name = "CryptoTest"
var _db_version = 1;
var _store_name = "KeyStore";

var _indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB || window.shimIndexedDB;
if (!_indexedDB)
{
	alert("Indexed Database API Not Supported");
	throw "Indexed Database API Not Supported";
}

var _db_handle = null;

function _openDb()
{
	return new Promise(function(resolve, reject) {
		let open = indexedDB.open("CryptoTest", 1);
		
		open.onupgradeneeded = function() {
			_db_handle = open.result;
			var transaction = _db_handle.createObjectStore(_store_name, {keyPath: "id"});
			transaction.oncomplete = function() {
				resolve();
			}
		};
		
		open.onsuccess = function() {
			_db_handle = open.result;
			resolve();
		};
		
		open.onblocked = function() {
			console.log("Database can't be upgraded because it is open")
			reject();
		}
	});
}

// Returns the key for the given keyId. If this does not exist returns null.
function loadKey(keyId)
{
	return new Promise(function(resolve, reject) {
		((_db_handle === null) ?
			_openDb() :
			Promise.resolve()
		).then(function() {
			let tx = _db_handle.transaction(_store_name, "readwrite");
			let store = tx.objectStore(_store_name);
    
			let getKey = store.get(keyId);

			getKey.onsuccess = function() {
				resolve(getKey.result ? getKey.result.key : null);
			};
			
			getKey.onerror = function() {
				reject(getKey.error);
			};
		});
	});
}

// Saves the given key to the given keyId.
function saveKey(keyId, keyObject)
{
	return new Promise(function(resolve, reject) {
		((_db_handle === null) ?
			_openDb() :
			Promise.resolve()
		).then(function() {
			let tx = _db_handle.transaction(_store_name, "readwrite");
			let store = tx.objectStore(_store_name);
			
			let putKey = store.put({id: keyId, key: keyObject});

			putKey.onsuccess = function() {
				resolve();
			};
			
			putKey.onerror = function() {
				reject(putKey.error);
			};
		});
	});
}

// Ensures no key with the given keyId exists
function deleteKey(keyId)
{
	return new Promise(function(resolve, reject) {
		((_db_handle === null) ?
			_openDb() :
			Promise.resolve()
		).then(function() {
			let tx = _db_handle.transaction(_store_name, "readwrite");
			let store = tx.objectStore(_store_name);
			
			let deleteKey = store.delete(keyId);

			deleteKey.onsuccess = function() {
				resolve();
			};
			
			deleteKey.onerror = function() {
				reject(deleteKey.error);
			};
		});
	});
}

//            /////////////////////////////////////////////

// Crypto     /////////////////////////////////////////////
// Uses Web Crypto API (SubtleCrypto)

var _crypto = window.crypto || window.msCrypto;
if (!_crypto)
{
	alert("Cryptography API Not Supported.");
	throw 'Cryptography API Not Supported.';
}

var _algorithm = "AES-CBC";
var _key_size = 256;
var _pbkdf_iterations = 100;

// Do not change this once used in production
var _defaultSalt = "af95a2b25229d223267a54fdec562c93";

// Generates a new Key
function _generateKey()
{
	// Extractable is set to false so that underlying key details cannot be accessed.
	return crypto.subtle.generateKey({name: _algorithm, length: _key_size}, false, ["encrypt", "decrypt"]);
}

// Derives a key from the given password.
// Salt is not required. If supplied should be a hex string.
function deriveKey(passphrase, salt)
{	
	if (typeof(salt) === 'undefined')
	{
		salt = _defaultSalt;
	}
	
	return passphrase == null || passphrase.length < 10 ?
		Promise.reject("Password must be at least 10 characters") :
		crypto.subtle.importKey(
			'raw',
			stringToUtf8ByteArray(passphrase),
			{ name: 'PBKDF2'},
			false,
			['deriveBits', 'deriveKey' ]
		).then(function(passwordKey) {
			return crypto.subtle.deriveKey(
				{
					"name": 'PBKDF2',
					"salt": hexStringToByteArray(salt),
					"iterations": _pbkdf_iterations,
					"hash": 'SHA-256'
				},
				passwordKey,
				{ "name": _algorithm, "length": _key_size },
				false, // Extractable is set to false so that underlying key details cannot be accessed.
				[ "encrypt", "decrypt" ]
			);
		});
}


function encryptData(keyObject, data)
{
	let iv = crypto.getRandomValues(new Uint8Array(16));
	
	return crypto.subtle.encrypt(
		{name: _algorithm, iv: iv},
		keyObject,
		data
	).then(function(encryptedData) {
		return {
			iv:iv,
			data:encryptedData
		}
	});
}

function decryptData(keyObject, iv, encryptedData)
{	
	return crypto.subtle.decrypt(
		{name: _algorithm, iv: iv},
		keyObject,
		encryptedData
	);
}

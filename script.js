document.getElementById('encryptBtn').onclick = function() {
    const text = document.getElementById('inputText').value;
    const password = document.getElementById('password').value;
    const password2 = document.getElementById('password2').value;
    const result = encrypt(text, password, password2);
    document.getElementById('outputText').value = result;
    alert('Результат шифрования: ' + result);
    console.log('ENCRYPTED:', result);
};

document.getElementById('decryptBtn').onclick = function() {
    const text = document.getElementById('outputText').value;
    const password = document.getElementById('password').value;
    const password2 = document.getElementById('password2').value;
    const result = decrypt(text, password, password2);
    document.getElementById('inputText').value = result;
    alert('Результат дешифрования: ' + result);
    console.log('DECRYPTED:', result);
};

function encrypt(text, password, password2) {

    const vigenereKey1 = generateDeterministicVigenereKey(password, text.length);
    const vigenere1 = vigenereEncrypt(text, vigenereKey1);

    const caesarShifted = caesarRandomShift(vigenere1, password);

    const atbash = atbashCipher(caesarShifted);

    let afterVigenere2 = atbash;
    if (password2 && password2.trim().length > 0) {
        const vigenereKey2 = generateDeterministicVigenereKey(password2, atbash.length);
        afterVigenere2 = vigenereEncrypt(atbash, vigenereKey2);
    }

    const binary = toBinary(afterVigenere2);
    return binary;
}


function seededRandom(seed) {
    let h = 2166136261 >>> 0;
    for (let i = 0; i < seed.length; i++) {
        h ^= seed.charCodeAt(i);
        h = Math.imul(h, 16777619);
    }
    return function() {
        h += h << 13; h ^= h >>> 7;
        h += h << 3;  h ^= h >>> 17;
        h += h << 5;
        return (h >>> 0) / 4294967295;
    };
}

const RUSSIAN_ALPHABET = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя';

function caesarRandomShift(text, password) {
    const rand = seededRandom(password);
    let result = '';
    for (let char of text) {
        const lowerChar = char.toLowerCase();
        const isUpper = char !== lowerChar;
        const idx = RUSSIAN_ALPHABET.indexOf(lowerChar);
        if (idx === -1) {
            result += char;
            continue;
        }

        const shift = 1 + Math.floor(rand() * 22);
        let newIdx = (idx + shift) % RUSSIAN_ALPHABET.length;
        let newChar = RUSSIAN_ALPHABET[newIdx];
        if (isUpper) newChar = newChar.toUpperCase();
        result += newChar;
    }
    return result;
}

function decrypt(text, password, password2) {

    let afterVigenere2 = fromBinary(text);

    let atbash = afterVigenere2;
    if (password2 && password2.trim().length > 0) {
        const vigenereKey2 = generateDeterministicVigenereKey(password2, afterVigenere2.length);
        atbash = vigenereDecrypt(afterVigenere2, vigenereKey2);
    }

    const caesarShifted = atbashCipher(atbash);

    const vigenere1 = caesarRandomShiftReverse(caesarShifted, password);
    // 5. Виженер (обратно)
    const vigenereKey1 = generateDeterministicVigenereKey(password, vigenere1.length);
    const original = vigenereDecrypt(vigenere1, vigenereKey1);
    return original;
}

function atbashCipher(text) {
    const abc = RUSSIAN_ALPHABET;
    const reversed = abc.split('').reverse().join('');
    let result = '';
    for (let char of text) {
        const lowerChar = char.toLowerCase();
        const isUpper = char !== lowerChar;
        const idx = abc.indexOf(lowerChar);
        if (idx === -1) {
            result += char;
            continue;
        }
        let newChar = reversed[idx];
        if (isUpper) newChar = newChar.toUpperCase();
        result += newChar;
    }
    return result;
}

function toBinary(text) {
    return text.split('').map(c => {
        let bin = c.charCodeAt(0).toString(2);
        return bin.padStart(8, '0');
    }).join(' ');
}

function fromBinary(binary) {
    return binary.split(' ').map(b => String.fromCharCode(parseInt(b, 2))).join('');
}


function caesarRandomShiftReverse(text, password) {
    const rand = seededRandom(password);
    let result = '';
    for (let char of text) {
        const lowerChar = char.toLowerCase();
        const isUpper = char !== lowerChar;
        const idx = RUSSIAN_ALPHABET.indexOf(lowerChar);
        if (idx === -1) {
            result += char;
            continue;
        }
        const shift = 1 + Math.floor(rand() * 22);
        let newIdx = (idx - shift + RUSSIAN_ALPHABET.length) % RUSSIAN_ALPHABET.length;
        let newChar = RUSSIAN_ALPHABET[newIdx];
        if (isUpper) newChar = newChar.toUpperCase();
        result += newChar;
    }
    return result;
}


function generateDeterministicVigenereKey(password, length) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=~[]{};:,.<>/?';

    const rand = seededRandom(password + ':' + length);
    const keyLength = 3 + Math.floor(rand() * 8); 
    let key = '';
    let lastChar = '';
    for (let i = 0; i < keyLength; i++) {
        let nextChar;
        let attempts = 0;
        do {
            nextChar = chars[Math.floor(rand() * chars.length)];
            attempts++;
        } while (nextChar === lastChar && attempts < 10);
        key += nextChar;
        lastChar = nextChar;
    }

    while (key.length < length) key += key;
    return key.slice(0, length);
}


function vigenereEncrypt(text, key) {
    let result = '';
    for (let i = 0, j = 0; i < text.length; i++) {
        const char = text[i];
        const lowerChar = char.toLowerCase();
        const isUpper = char !== lowerChar;
        const idx = RUSSIAN_ALPHABET.indexOf(lowerChar);
        if (idx === -1) {
            result += char;
            continue;
        }
        const keyChar = key[j].toLowerCase();
        const keyIdx = RUSSIAN_ALPHABET.indexOf(keyChar);
        if (keyIdx === -1) {
            result += char;
            continue;
        }
        let newIdx = (idx + keyIdx) % RUSSIAN_ALPHABET.length;
        let newChar = RUSSIAN_ALPHABET[newIdx];
        if (isUpper) newChar = newChar.toUpperCase();
        result += newChar;
        j++;
    }
    return result;
}

function vigenereDecrypt(text, key) {
    let result = '';
    for (let i = 0, j = 0; i < text.length; i++) {
        const char = text[i];
        const lowerChar = char.toLowerCase();
        const isUpper = char !== lowerChar;
        const idx = RUSSIAN_ALPHABET.indexOf(lowerChar);
        if (idx === -1) {
            result += char;
            continue;
        }
        const keyChar = key[j].toLowerCase();
        const keyIdx = RUSSIAN_ALPHABET.indexOf(keyChar);
        if (keyIdx === -1) {
            result += char;
            continue;
        }
        let newIdx = (idx - keyIdx + RUSSIAN_ALPHABET.length) % RUSSIAN_ALPHABET.length;
        let newChar = RUSSIAN_ALPHABET[newIdx];
        if (isUpper) newChar = newChar.toUpperCase();
        result += newChar;
        j++;
    }
    return result;
}


function generateRandomVigenereKey(password) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=~[]{};:,.<>/?';

    const rand = seededRandom(password + 'vigenere');
    const length = 1 + Math.floor(rand() * 9);
    let key = '';
    for (let i = 0; i < length; i++) {
        key += chars[Math.floor(rand() * chars.length)];
    }
    return key;
}

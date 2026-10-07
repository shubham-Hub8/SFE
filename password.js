/* ==========================================
   Simple File Encryptor 3.0
   Password Management
========================================== */

"use strict";

const MIN_NEW_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 128;

const COMMON_WEAK_PASSWORDS = new Set([
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "password",
    "password1",
    "password123",
    "qwerty",
    "qwerty123",
    "letmein",
    "welcome",
    "admin",
    "admin123",
    "iloveyou",
    "abc123",
    "trustno1",
    "princess",
    "football",
    "monkey",
    "dragon",
    "sunshine",
    "master",
    "welcome1",
    "letmein123",
    "11111111",
    "00000000"
]);

function normalizedPasswordForChecks(password) {
    return typeof password.normalize === "function"
        ? password.normalize("NFC")
        : password;
}

function passwordLength(password) {
    return Array.from(normalizedPasswordForChecks(password)).length;
}

function isObviousWeakPassword(password) {
    const normalized = normalizedPasswordForChecks(password).toLowerCase();

    if (COMMON_WEAK_PASSWORDS.has(normalized)) {
        return true;
    }

    const highRiskComponents = [
        "password", "qwerty", "letmein", "admin", "welcome",
        "trustno1", "iloveyou", "abc123"
    ];

    if (highRiskComponents.some(component => normalized.includes(component))) {
        return true;
    }

    if (normalized.length >= 4 && /^(.)\1+$/.test(normalized)) {
        return true;
    }

    if (hasSequentialRun(normalized, 4)) {
        return true;
    }

    if (hasKeyboardRun(normalized)) {
        return true;
    }

    if (hasRepeatedChunk(normalized)) {
        return true;
    }

    return false;
}

function hasSequentialRun(value, minimumRun = 4) {
    const chars = Array.from(value);

    if (chars.length < minimumRun) {
        return false;
    }

    for (let i = 0; i <= chars.length - minimumRun; i += 1) {
        let ascending = true;
        let descending = true;

        for (let j = 1; j < minimumRun; j += 1) {
            const previous = chars[i + j - 1].codePointAt(0);
            const current = chars[i + j].codePointAt(0);

            if (current !== previous + 1) {
                ascending = false;
            }

            if (current !== previous - 1) {
                descending = false;
            }
        }

        if (ascending || descending) {
            return true;
        }
    }

    return false;
}

function hasKeyboardRun(value) {
    const keyboardRuns = [
        "qwer", "wert", "erty", "rtyu", "tyui", "yuio", "uiop",
        "asdf", "sdfg", "dfgh", "fghj", "ghjk", "hjkl",
        "zxcv", "xcvb", "cvbn", "1234", "2345", "3456", "4567",
        "5678", "6789", "7890"
    ];

    return keyboardRuns.some(run => value.includes(run) || value.includes(run.split("").reverse().join("")));
}

function hasRepeatedChunk(value) {
    const length = value.length;

    if (length < 4) {
        return false;
    }

    // Detect an adjacent repeated substring even when the password contains
    // a suffix/prefix around it, e.g. "passwordpassword123".
    for (let chunkLength = 2; chunkLength <= Math.min(8, Math.floor(length / 2)); chunkLength += 1) {
        for (let start = 0; start + (chunkLength * 2) <= length; start += 1) {
            const chunk = value.slice(start, start + chunkLength);

            if (chunk === value.slice(start + chunkLength, start + (chunkLength * 2))) {
                return true;
            }
        }
    }

    return false;
}

DOM.showPassword.addEventListener("change", () => {
    const type = DOM.showPassword.checked ? "text" : "password";
    DOM.password.type = type;
    DOM.confirmPassword.type = type;
});

DOM.password.addEventListener("input", updatePasswordStrength);
DOM.confirmPassword.addEventListener("input", validatePasswordMatch);

function updatePasswordStrength() {
    const password = DOM.password.value;
    const strength = calculateStrength(password);

    if (password.length === 0) {
        DOM.strength.textContent = "Strength: —";
        DOM.strength.style.color = "";
        if (DOM.strengthScore) DOM.strengthScore.textContent = "0/100";
        if (DOM.strengthMeterBar) {
            DOM.strengthMeterBar.style.width = "0%";
            DOM.strengthMeterBar.style.background = "";
        }
        if (DOM.strengthAdvice) {
            DOM.strengthAdvice.textContent = "Use a long, unique password. This tracker estimates predictability; it does not measure exact entropy.";
        }
        DOM.strength.title = "";
        DOM.strength.setAttribute("aria-label", "Password strength: empty");
        validatePasswordMatch();
        return;
    }

    DOM.strength.textContent = `Strength: ${strength.label}`;
    DOM.strength.style.color = strength.color;
    if (DOM.strengthScore) DOM.strengthScore.textContent = `${strength.score}/100`;
    if (DOM.strengthMeterBar) {
        DOM.strengthMeterBar.style.width = `${strength.score}%`;
        DOM.strengthMeterBar.style.background = strength.color;
    }
    if (DOM.strengthAdvice) DOM.strengthAdvice.textContent = strength.explanation;
    DOM.strength.title = strength.explanation;
    DOM.strength.setAttribute("aria-label", `Password strength: ${strength.label}, ${strength.score} out of 100`);

    validatePasswordMatch();
}

function validatePasswordMatch() {
    const password = DOM.password.value;
    const confirm = DOM.confirmPassword.value;

    if (confirm.length === 0) {
        DOM.confirmPassword.style.borderColor = "";
        return true;
    }

    if (password === confirm) {
        DOM.confirmPassword.style.borderColor = "var(--success)";
        return true;
    }

    DOM.confirmPassword.style.borderColor = "var(--danger)";
    return false;
}

function calculateStrength(password) {
    const normalized = normalizedPasswordForChecks(password);
    const length = passwordLength(normalized);

    if (length === 0) {
        return {
            label: "—",
            score: 0,
            color: "",
            explanation: "Enter a password."
        };
    }

    const weak = isObviousWeakPassword(normalized);
    const classes = [
        /[a-z]/.test(normalized),
        /[A-Z]/.test(normalized),
        /\d/.test(normalized),
        /[^\p{L}\p{N}\s]/u.test(normalized)
    ].filter(Boolean).length;

    const uniqueCharacters = new Set(Array.from(normalized)).size;
    const uniquenessRatio = uniqueCharacters / Math.max(1, length);

    // This is a local heuristic meter, not a claim of measured cryptographic entropy.
    let score = Math.min(45, Math.round(length * 2.8));
    score += classes * 7;
    score += Math.min(12, Math.round(uniquenessRatio * 12));

    const repeated = hasRepeatedChunk(normalized.toLowerCase());
    const sequential = hasSequentialRun(normalized.toLowerCase(), 4);
    const keyboard = hasKeyboardRun(normalized.toLowerCase());

    if (repeated) score -= 22;
    if (sequential) score -= 18;
    if (keyboard) score -= 18;

    // Common-password rejection dominates the score so a long but predictable
    // value does not get presented as strong.
    if (weak) {
        score -= 60;
    }

    score = Math.max(0, Math.min(100, score));

    let label;
    let color;

    if (weak || score < 30) {
        label = "Very weak";
        color = "var(--danger)";
    } else if (score < 50) {
        label = "Weak";
        color = "var(--danger)";
    } else if (score < 70) {
        label = "Fair";
        color = "var(--warning)";
    } else if (score < 85) {
        label = "Strong";
        color = "var(--success)";
    } else {
        label = "Very strong";
        color = "var(--success)";
    }

    const reasons = [];

    if (length < MIN_NEW_PASSWORD_LENGTH) {
        reasons.push(`use at least ${MIN_NEW_PASSWORD_LENGTH} characters for new SFE3 encryption`);
    }

    if (weak) {
        reasons.push("avoid common, repeated, sequential, or keyboard-pattern passwords");
    } else {
        if (classes < 2) reasons.push("mix more than one character type");
        if (length < 16) reasons.push("more length would improve resistance to guessing");
    }

    if (reasons.length === 0) {
        reasons.push("good length and low obvious-pattern risk");
    }

    return {
        label,
        score,
        color,
        explanation: `Heuristic tracker: ${reasons.join("; ")}. This meter estimates predictability; it does not measure exact entropy.`
    };
}

function validatePassword() {
    const password = DOM.password.value;
    const confirm = DOM.confirmPassword.value;
    const length = passwordLength(password);

    if (length === 0) {
        setStatus("Please enter a password.");
        DOM.password.focus();
        return false;
    }

    if (length > MAX_PASSWORD_LENGTH) {
        setStatus(`Password must be ${MAX_PASSWORD_LENGTH} characters or fewer.`);
        DOM.password.focus();
        return false;
    }

    if (State.mode === "encrypt") {
        if (length < MIN_NEW_PASSWORD_LENGTH) {
            setStatus(`New SFE3 encryption passwords must be at least ${MIN_NEW_PASSWORD_LENGTH} characters long.`);
            DOM.password.focus();
            return false;
        }

        if (isObviousWeakPassword(password)) {
            setStatus("That password is too easy to guess. Choose a longer, less predictable password or use a password generator.");
            DOM.password.focus();
            return false;
        }

        if (password !== confirm) {
            setStatus("Passwords do not match.");
            DOM.confirmPassword.focus();
            return false;
        }
    }

    return true;
}

function getPassword() {
    return DOM.password.value;
}


function generateSecurePassword(length = 32) {
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+[]{}";
    const targetLength = Math.min(MAX_PASSWORD_LENGTH, Math.max(MIN_NEW_PASSWORD_LENGTH, Number(length) || 32));
    const output = new Array(targetLength);
    const max = Math.floor(0x100000000 / alphabet.length) * alphabet.length;
    const buffer = new Uint32Array(32);
    let index = 0;

    while (index < targetLength) {
        crypto.getRandomValues(buffer);
        for (const value of buffer) {
            if (value >= max) continue;
            output[index++] = alphabet[value % alphabet.length];
            if (index === targetLength) break;
        }
    }

    return output.join("");
}

function fillGeneratedPassword() {
    const generated = generateSecurePassword(32);
    DOM.password.value = generated;
    DOM.confirmPassword.value = generated;
    updatePasswordStrength();
    DOM.password.dispatchEvent(new Event("input", { bubbles: true }));
    DOM.password.focus();
}

if (DOM.generatePassword) {
    DOM.generatePassword.addEventListener("click", fillGeneratedPassword);
}

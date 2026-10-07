Simple File Encryptor

Local file encryption built around privacy, security, and keeping your files on your own device.

"Open SFE" (https://sfesecure.netlify.app)

SFE (Simple File Encryptor) is an open-source file encryption tool that runs directly in your browser. It is designed for people who want to encrypt files without uploading them to a server, creating an account, or handing their files over to an online service.

Everything happens locally in your browser.

What SFE does

SFE encrypts files using AES-256-GCM, with Argon2id used for password-based key derivation.

The basic flow is:

1. Select a file or folder.
2. Choose your Argon2id settings.
3. Enter a password.
4. SFE derives an encryption key from the password.
5. The file is encrypted locally.
6. The encrypted file is saved back to your device.

Decryption works the same way in reverse. The correct password is required to recover the original file.

Your files are not uploaded to SFE's servers because SFE does not need a server to perform the encryption.

Why I made it

A lot of file encryption tools make simple encryption feel more complicated than it needs to be. Others require an account or send files to a remote service.

I wanted something that was straightforward:

Pick a file → enter a password → encrypt it → keep the encrypted file.

SFE is also meant to be understandable. The encryption settings are exposed instead of hiding everything behind a single "Secure" button.

Security

SFE uses modern cryptographic primitives rather than trying to create its own encryption algorithm.

AES-256-GCM

AES-256-GCM is used for the actual file encryption.

It provides both confidentiality and authentication, which means the encrypted data cannot simply be modified without the change being detected during decryption.

Argon2id

Passwords are not used directly as AES keys.

SFE uses Argon2id to derive a cryptographic key from the password. Argon2id is designed to make password guessing more expensive by requiring both computation and memory.

SFE lets you adjust the Argon2id resource settings, including the memory cost and iteration settings.

Higher settings require more resources and can take longer to process. The right setting depends on the device being used.

Salts

A unique salt is generated for password-based key derivation.

This prevents the same password from producing the same derived key across different encryption operations.

IVs / nonces

AES-GCM requires a unique nonce for encryption. SFE generates a new value for each encryption operation instead of reusing one.

Reusing a GCM nonce with the same key can seriously compromise security, so this is an important part of the encryption process.

Privacy

SFE is designed around local processing.

There is:

- No account system
- No file upload service
- No server-side encryption
- No cloud storage requirement
- No need to send your password anywhere

The browser performs the cryptographic work on your device.

That does not magically make a device secure. If your phone or computer is compromised, malware or someone with access to the device may still be able to access files or passwords while you are using SFE.

Features

- AES-256-GCM file encryption
- Argon2id password-based key derivation
- Adjustable Argon2id memory cost
- Adjustable iteration settings
- Random salts
- Random encryption nonces
- Local browser-based processing
- File encryption without uploading files
- File decryption
- Support for large files
- Works without an account
- Open-source
- Designed to work directly in a modern browser

How the password is handled

Your password is used locally to derive the encryption key.

SFE does not need to send the password to a server because there is no server involved in the encryption process.

This is also why losing your password is a serious problem.

There is no SFE account recovery system that can give you the original password back.

If you lose the password used to encrypt a file, the encrypted file may be unrecoverable.

Keep important passwords somewhere safe.

How the encrypted file works

The encrypted file contains the information needed for SFE to know how to process it during decryption, including the parameters needed for key derivation and encryption.

The password itself is not stored inside the encrypted file.

When you try to decrypt it, SFE derives the key again using the stored parameters and the password you provide.

If the password is wrong or the encrypted data has been modified, authentication fails and the file cannot be successfully decrypted.

Resource settings

Argon2id can use a significant amount of memory depending on the settings you choose.

This is intentional.

Password-based encryption needs to make brute-force attacks expensive, and memory usage is one of the things Argon2id uses to achieve that.

There is a tradeoff:

Higher settings = more resistance to password guessing, but more work for your device.

On a phone or lower-end device, extremely high memory settings may take noticeably longer or may fail if the browser cannot allocate enough memory.

Use a setting that your device can handle reliably.

Browser-based does not mean "uploaded"

SFE is a web application, but the encryption itself happens locally.

Opening SFE in your browser does not mean your selected files are automatically sent to a server for encryption.

The web app provides the interface and the code. Your files stay on your device while the encryption operation is performed.

Open source

SFE is open source.

You can inspect the source code, see how the encryption process is implemented, report problems, suggest improvements, or build your own version.

That matters for a security tool because you should not have to blindly trust a black box.

GitHub:

"View the source code" (https://github.com/shubham-Hub8/File-encrypter-)

Things to keep in mind

SFE protects the files you encrypt. It does not protect your entire device.

A strong encryption system can still be undermined by:

- A weak password
- Malware on the device
- Someone accessing your unlocked device
- Losing the password
- Accidentally deleting the only copy of an important file
- Using an outdated or compromised browser

Encryption is only one part of keeping data secure.

For important files, keep a backup of the encrypted file somewhere safe.

Who is SFE for?

SFE is useful if you want to:

- Keep personal files encrypted on your device
- Store sensitive documents more safely
- Encrypt files before putting them on cloud storage
- Send someone an encrypted file separately from its password
- Experiment with modern browser-based cryptography
- Learn how password-based file encryption works

You don't need an account or a complicated setup to get started.

Getting started

Go to:

https://sfesecure.netlify.app

Choose your file, select your encryption settings, enter a strong password, and encrypt it.

Keep the encrypted file and your password safe.

That's it.

Technology

SFE is built as a client-side web application using standard web technologies and WebAssembly-based cryptographic functionality.

The main cryptographic components are:

- AES-256-GCM for authenticated encryption
- Argon2id for password-based key derivation
- Random salts for password derivation
- Random nonces/IVs for encryption

No custom encryption algorithm is being used.

Project status

SFE 3.0 is the current version of the project.

The project is still open to improvements, bug fixes, security reviews, and ideas. If you find something that looks wrong, please open an issue or contribute a fix.

License

See the repository for the project's license and source code.

---

Made as a small, practical encryption tool for people who want control over their own files.

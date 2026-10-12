# LogonStealer

> Abuses the Credential Provider COM interface to steal plaintext passwords from logonui.exe via CredProvDataModel.dll hooks

A Windows credential stealer implemented as a rogue Credential Provider DLL. It loads automatically into `logonui.exe` via COM registration (bypassing PPL) and hooks `CredProvDataModel.dll` to capture plaintext passwords at the Windows logon and lock screen

---

## How it works

Windows loads all registered Credential Providers into `logonui.exe` via `CoCreateInstance`.

On modern Windows 11, the password input does not pass through the classic `ICredentialProviderCredential::SetStringValue` method. Instead, it flows through a WinRT stack:

```
Windows.UI.Logon.dll
└── textinputframework.dll
└── CredProvDataModel.dll <- hook point
└── ICredentialProvider (classic COM)
└── winlogon (via WNF)
```
The `EditField` object inside `CredProvDataModel.dll` manages the password field. Its `put_Value` method (vtable slot 7) is called on every keystroke with the accumulated value, and `get_Value` (slot 6) is called at submit time with the final value. Both are hooked with Microsoft Detours.

## Technique

**CredProvDataModel EditField Hook**, hooks `put_Value` and `get_Value` on the WinRT `EditField` object inside `CredProvDataModel.dll`. This captures the password in plaintext regardless of which Credential Provider the user selects (password, domain, RDP, etc.).

Functions are resolved by **byte pattern scan** over the `.text` section of `CredProvDataModel.dll`, so no hardcoded RVAs or version pinning are required.

## Files and Projects

- **LocalCredStealerCP**: the main DLL source. This is the compiled Credential Provider that gets loaded into logonui.exe. 
- **registerCP.bat**: installs the CP. Writes the registry keys needed. Needs to run as Administrator. After this, the next logon loads the DLL into logonui.exe.
- **unregisterCP.cmd**: reverses registerCP.bat. Deletes the same registry keys so Windows stops loading the DLL on logon. Also needs to run as Administrator.

## Deployment
- Replace the DLL path inside the **registerCP.bat**
- Execute the **registerCP.bat** as Administrator
- Sign out or restart
- Login
- Check the **C:\cred_capture.log** with the entered password

# Notes

### Version 1
- Handle SSL offload scenario
```xml
<Federation ....>
  <AllowUnsecureSessionCookie>true</AllowUnsecureSessionCookie>  // default "false"
...
<Federation>
```
- Handle ReturnUrl in LogoutHandler
- PostGreSQL session store support
- Fixes to accommodate NemLog-in integration tests (error messages)
- Assertion timeout configurable on IDP

```xml
<appSettings>
  <add key="AssertionTimeoutMinutes" value="1"/>  // default "60"
...
<appSettings>
```

### Version 1.1
- Fix message content when assertion does not have the required Level of Assurance and always show this message

### Version 1.2
- LoA too low stops execution in handler. Added redirect setting if LoA too low
```xml
<SAML20Federation ....>
  <MinimumNsisLoaViolatedRedirectUrl>/loatoolow</MinimumNsisLoaViolatedRedirectUrl>  // default ""
...
<SAML20Federation>
```

### Version 1.3
- "Unsecure cookie" changes too harsh. Cookie settings now back to orginal implementation. Custom secure connection check remains.


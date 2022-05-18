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



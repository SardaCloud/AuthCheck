## Downloads

Pick the package for the machine you will run AuthCheck **on**.

| Package | For |
| --- | --- |
| `AuthCheck-VERSION-win-x64.zip` | 64-bit Intel or AMD. Almost certainly the one you want |
| `AuthCheck-VERSION-win-arm64.zip` | Windows on ARM |
| `AuthCheck-VERSION-win-x86.zip` | 32-bit Windows |

Each holds one self-contained `AuthCheck.exe`: unzip it anywhere and run it.
Nothing needs installing, and no .NET runtime is required.

### Verifying a download

```powershell
(Get-FileHash .\AuthCheck-VERSION-win-x64.zip -Algorithm SHA256).Hash.ToLower()
```

Compare it with `SHA256SUMS.txt`.

---

Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
Licensed under the [MIT License](https://github.com/SardaCloud/AuthCheck/blob/main/LICENSE).
